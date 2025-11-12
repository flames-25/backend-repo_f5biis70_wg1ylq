import os
import difflib
import re
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import CodeReview, Finding

app = FastAPI(title="AI-Powered Code Review & Optimization Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewResponse(BaseModel):
    id: str
    filename: str
    language: Optional[str] = None
    original_code: str
    optimized_code: Optional[str] = None
    diff: Optional[str] = None
    findings: List[Finding] = []
    metrics: Dict[str, Any] = {}
    summary: Optional[str] = None


# ------------------- Simple Static Analyzer -------------------
SECURITY_PATTERNS = [
    (r"\beval\(.*\)", "Use of eval can be dangerous and lead to code injection", "high"),
    (r"\bexec\(.*\)", "Use of exec can be dangerous and lead to code injection", "high"),
    (r"subprocess\.Popen\(.*shell=True.*\)", "shell=True with subprocess can lead to shell injection", "critical"),
    (r"\bpickle\.loads\(.*\)", "Untrusted pickle.loads can execute arbitrary code", "high"),
]

QUALITY_PATTERNS = [
    (r"==\s*None", "Use 'is None' instead of '== None'", "medium"),
    (r"!=\s*None", "Use 'is not None' instead of '!= None'", "medium"),
    (r"\bprint\(.*\)", "Avoid prints in production; use logging instead", "low"),
    (r"except\s*:\s*", "Bare except catches all exceptions; catch specific exceptions", "high"),
]

SECRET_PATTERNS = [
    (r"AWS_SECRET|API_KEY|SECRET_KEY|PASSWORD\s*=\s*['\"][^'\"]+['\"]", "Possible hardcoded secret detected", "high"),
]


def estimate_complexity(code: str) -> int:
    tokens = [" for ", " while ", " if ", " elif ", " and ", " or ", " try:", " except ", " with "]
    return sum(code.count(t) for t in tokens)


def optimize_code(code: str) -> str:
    optimized = code
    # Replace == None / != None
    optimized = re.sub(r"==\s*None", "is None", optimized)
    optimized = re.sub(r"!=\s*None", "is not None", optimized)
    # Replace prints with logging placeholder comments
    optimized = re.sub(r"\bprint\((.*?)\)", r"# TODO: replace with logging.debug(\1)", optimized)
    return optimized


def analyze_code(filename: str, code: str, language: Optional[str] = None) -> CodeReview:
    findings: List[Finding] = []

    # Bugs / quality / security patterns
    for pattern, message, severity in SECURITY_PATTERNS:
        for m in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
            findings.append(Finding(type="security", severity=severity, message=message, line=None, snippet=m.group(0)))
    for pattern, message, severity in QUALITY_PATTERNS:
        for m in re.finditer(pattern, code, re.MULTILINE):
            findings.append(Finding(type="quality", severity=severity, message=message, line=None, snippet=m.group(0)))
    for pattern, message, severity in SECRET_PATTERNS:
        for m in re.finditer(pattern, code, re.MULTILINE):
            findings.append(Finding(type="security", severity=severity, message=message, line=None, snippet=m.group(0)))

    # Simple bug heuristics
    if re.search(r"\bmutable default args\b", code, re.IGNORECASE):
        findings.append(Finding(type="bug", severity="high", message="Possible mutable default arguments", snippet=None))

    lines = code.splitlines()
    loc = len(lines)
    long_lines = sum(1 for l in lines if len(l) > 120)
    complexity = estimate_complexity(code)

    metrics: Dict[str, Any] = {
        "loc": loc,
        "long_lines": long_lines,
        "complexity_estimate": complexity,
    }

    optimized = optimize_code(code) if code else code

    diff_text = None
    if optimized != code:
        diff = difflib.unified_diff(
            code.splitlines(), optimized.splitlines(),
            fromfile=f"a/{filename}", tofile=f"b/{filename}", lineterm=""
        )
        diff_text = "\n".join(list(diff))

    summary_parts = []
    if findings:
        summary_parts.append(f"Identified {len(findings)} potential issues across security/quality categories.")
    summary_parts.append(f"Lines: {loc}, Long lines (>120 chars): {long_lines}, Complexity estimate: {complexity}.")
    if optimized != code:
        summary_parts.append("Proposed small safe improvements (None comparisons, print usage).")

    return CodeReview(
        filename=filename,
        language=language,
        original_code=code,
        optimized_code=optimized,
        diff=diff_text,
        findings=findings,
        metrics=metrics,
        summary=" ".join(summary_parts)
    )


# ------------------- API Routes -------------------
@app.get("/")
def read_root():
    return {"message": "AI Code Review Backend Running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


@app.post("/api/reviews/analyze", response_model=ReviewResponse)
async def analyze_file(file: UploadFile = File(...), language: Optional[str] = Form(None)):
    try:
        content_bytes = await file.read()
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Fallback for other encodings
            content = content_bytes.decode("latin-1", errors="ignore")
        review = analyze_code(file.filename, content, language)
        # Persist
        review_id = create_document("codereview", review)
        return ReviewResponse(
            id=review_id,
            filename=review.filename,
            language=review.language,
            original_code=review.original_code,
            optimized_code=review.optimized_code,
            diff=review.diff,
            findings=review.findings,
            metrics=review.metrics,
            summary=review.summary,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/reviews", response_model=List[ReviewResponse])
async def list_reviews(limit: int = 20):
    docs = get_documents("codereview", {}, limit)
    results: List[ReviewResponse] = []
    for d in docs[::-1]:  # newest last in query; reverse for newest first
        results.append(ReviewResponse(
            id=str(d.get("_id")),
            filename=d.get("filename"),
            language=d.get("language"),
            original_code=d.get("original_code"),
            optimized_code=d.get("optimized_code"),
            diff=d.get("diff"),
            findings=[Finding(**f) for f in d.get("findings", [])],
            metrics=d.get("metrics", {}),
            summary=d.get("summary"),
        ))
    return results


@app.get("/api/reviews/{review_id}", response_model=ReviewResponse)
async def get_review(review_id: str):
    try:
        doc = db["codereview"].find_one({"_id": ObjectId(review_id)})
        if not doc:
            raise HTTPException(status_code=404, detail="Review not found")
        return ReviewResponse(
            id=str(doc.get("_id")),
            filename=doc.get("filename"),
            language=doc.get("language"),
            original_code=doc.get("original_code"),
            optimized_code=doc.get("optimized_code"),
            diff=doc.get("diff"),
            findings=[Finding(**f) for f in doc.get("findings", [])],
            metrics=doc.get("metrics", {}),
            summary=doc.get("summary"),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/reviews/rediff/{review_id}", response_model=ReviewResponse)
async def re_diff(review_id: str):
    doc = db["codereview"].find_one({"_id": ObjectId(review_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Review not found")
    orig = doc.get("original_code", "")
    opt = doc.get("optimized_code", "")
    if orig and opt:
        diff = difflib.unified_diff(orig.splitlines(), opt.splitlines(), fromfile=f"a/{doc.get('filename')}", tofile=f"b/{doc.get('filename')}", lineterm="")
        diff_text = "\n".join(list(diff))
    else:
        diff_text = None
    db["codereview"].update_one({"_id": doc["_id"]}, {"$set": {"diff": diff_text}})
    updated = db["codereview"].find_one({"_id": doc["_id"]})
    return ReviewResponse(
        id=str(updated.get("_id")),
        filename=updated.get("filename"),
        language=updated.get("language"),
        original_code=updated.get("original_code"),
        optimized_code=updated.get("optimized_code"),
        diff=updated.get("diff"),
        findings=[Finding(**f) for f in updated.get("findings", [])],
        metrics=updated.get("metrics", {}),
        summary=updated.get("summary"),
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
