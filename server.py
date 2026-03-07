from fastapi import FastAPI, APIRouter, HTTPException, Query, Depends, Request, UploadFile, File, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import re
import jwt
import hashlib
import asyncio
from collections import defaultdict
try:
    from PIL import Image
    import io
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
import shutil
import httpx

ROOT_DIR = Path(__file__).parent
UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
from starlette.middleware.gzip import GZipMiddleware

# ==================== RATE LIMITER ====================
# Stockage en mémoire : {ip: [timestamps]}
_rate_limit_store = defaultdict(list)

def check_rate_limit(request: Request, max_requests: int = 5, window_seconds: int = 60):
    """Vérifie et applique le rate limiting par IP"""
    ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc).timestamp()
    window_start = now - window_seconds
    
    # Nettoyer les anciennes entrées
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if t > window_start]
    
    if len(_rate_limit_store[ip]) >= max_requests:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Réessayez dans {window_seconds} secondes."
        )
    
    _rate_limit_store[ip].append(now)

async def auto_publish_scheduled_articles():
    """Publier automatiquement les articles dont la date programmée est passée"""
    await asyncio.sleep(5)  # Attendre que la DB soit connectée
    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()
            result = await db.articles.update_many(
                {
                    "is_published": False,
                    "scheduled_at": {"$ne": None, "$lte": now}
                },
                {"$set": {"is_published": True}}
            )
            if result.modified_count > 0:
                logger.info(f"{result.modified_count} article(s) publiés automatiquement")
        except Exception as e:
            logger.error(f"Erreur auto-publish: {e}")
        await asyncio.sleep(60)  # Vérifier toutes les minutes

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    asyncio.create_task(auto_publish_scheduled_articles())
    logger.info("Tâche auto-publication démarrée ✅")
    yield

app = FastAPI(lifespan=lifespan)
# Compression GZip automatique — réduit la taille des réponses JSON de ~70%
# Les navigateurs modernes envoient Accept-Encoding: gzip automatiquement
app.add_middleware(GZipMiddleware, minimum_size=500)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET = os.environ.get('ADMIN_PASSWORD', 'UnMotDePassePourTonSite2026!')

# Brevo (newsletter)
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')
BREVO_SENDER_EMAIL = os.environ.get('BREVO_SENDER_EMAIL', 'newsletter@theclassement.com')
BREVO_SENDER_NAME = os.environ.get('BREVO_SENDER_NAME', 'The Classement')

async def send_brevo_email(to_email: str, to_name: str, subject: str, html_content: str):
    """Envoyer un email via Brevo API"""
    if not BREVO_API_KEY:
        logger.warning("BREVO_API_KEY non configurée - email non envoyé")
        return False
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "api-key": BREVO_API_KEY,
                    "Content-Type": "application/json"
                },
                json={
                    "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
                    "to": [{"email": to_email, "name": to_name}],
                    "subject": subject,
                    "htmlContent": html_content
                },
                timeout=10.0
            )
            if response.status_code == 201:
                logger.info(f"Email envoyé à {to_email}")
                return True
            else:
                logger.error(f"Erreur Brevo {response.status_code}: {response.text}")
                return False
    except Exception as e:
        logger.error(f"Exception Brevo: {e}")
        return False

async def send_newsletter_to_all(subject: str, html_content: str):
    """Envoyer newsletter à tous les abonnés actifs"""
    subscribers = await db.newsletter.find({"is_active": True}, {"_id": 0}).to_list(10000)
    success_count = 0
    for sub in subscribers:
        ok = await send_brevo_email(sub["email"], sub["email"], subject, html_content)
        if ok:
            success_count += 1
    return {"sent": success_count, "total": len(subscribers)}
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 168  # 7 jours

security = HTTPBearer()


# ==================== AUTH MODELS ====================

class LoginRequest(BaseModel):
    password: str

class LoginResponse(BaseModel):
    token: str
    expires_at: str

class PasswordChange(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


# ==================== AUTH FUNCTIONS ====================

def create_token() -> tuple[str, datetime]:
    expires_at = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": "admin",
        "exp": expires_at.timestamp(),
        "iat": datetime.now(timezone.utc).timestamp()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expires_at

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")


# ==================== AUTH ENDPOINTS ====================

@api_router.post("/auth/login", response_model=LoginResponse)
async def admin_login(request: LoginRequest):
    # First check if password was changed and stored in DB
    db_password = await db.settings.find_one({"key": "admin_password"})
    if db_password:
        admin_password = db_password.get("value")
    else:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'UnMotDePassePourTonSite2026!')
    
    if not admin_password:
        raise HTTPException(status_code=500, detail="Configuration erreur")
    
    if request.password != admin_password:
        raise HTTPException(status_code=401, detail="Mot de passe incorrect")
    
    token, expires_at = create_token()
    return LoginResponse(token=token, expires_at=expires_at.isoformat())

@api_router.get("/auth/verify")
async def verify_admin(authenticated: bool = Depends(verify_token)):
    return {"valid": True}

@api_router.post("/auth/change-password")
async def change_admin_password(data: PasswordChange, authenticated: bool = Depends(verify_token)):
    """Change admin password"""
    admin_password = os.environ.get('ADMIN_PASSWORD', 'UnMotDePassePourTonSite2026!')
    
    # Verify old password
    if data.old_password != admin_password:
        raise HTTPException(status_code=401, detail="Ancien mot de passe incorrect")
    
    # Verify new password confirmation
    if data.new_password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Les mots de passe ne correspondent pas")
    
    # Validate new password
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins 8 caractères")
    
    # Store new password in database for persistence
    await db.settings.update_one(
        {"key": "admin_password"},
        {"$set": {"key": "admin_password", "value": data.new_password}},
        upsert=True
    )
    
    # Also update environment variable for current session
    os.environ['ADMIN_PASSWORD'] = data.new_password
    
    return {"success": True, "message": "Mot de passe modifié avec succès"}


# ==================== MODELS ====================

class RankingItem(BaseModel):
    rank: int
    title: str
    description: str
    image_url: Optional[str] = None
    link_url: Optional[str] = None
    link_text: Optional[str] = None

class ArticleBase(BaseModel):
    title: str
    slug: str
    image_url: str
    introduction: str
    category: str
    rankings: List[RankingItem]
    is_featured: bool = False
    show_on_homepage: bool = False
    is_top_of_month: bool = False

class ArticleCreate(ArticleBase):
    pass

class ArticleUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    image_url: Optional[str] = None
    introduction: Optional[str] = None
    category: Optional[str] = None
    rankings: Optional[List[RankingItem]] = None
    is_featured: Optional[bool] = None
    show_on_homepage: Optional[bool] = None
    is_top_of_month: Optional[bool] = None

class Article(ArticleBase):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    views: int = 0

# ==================== CATEGORY MODELS ====================

class CategoryBase(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    icon: str = "folder"  # lucide icon name
    color: str = "blue"   # tailwind color
    order: int = 0

class CategoryCreate(CategoryBase):
    pass

class CategoryUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None
    order: Optional[int] = None

class Category(CategoryBase):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ==================== BLOG MODELS ====================

class BlogCategoryBase(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None

class BlogCategoryCreate(BlogCategoryBase):
    pass

class BlogCategory(BlogCategoryBase):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class BlogArticleBase(BaseModel):
    title: str
    slug: str
    excerpt: str  # Short summary for listings
    content: str  # Full HTML/markdown content
    featured_image: str
    category: str  # Blog category slug
    tags: List[str] = []
    is_published: bool = True
    scheduled_at: Optional[str] = None  # Date de publication programmée
    scheduled_at: Optional[str] = None  # Date de publication programmée (ISO format)
    related_tops: List[str] = []  # Related Top 10 article slugs
    show_on_homepage: bool = False

class BlogArticleCreate(BlogArticleBase):
    pass

class BlogArticleUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    excerpt: Optional[str] = None
    content: Optional[str] = None
    featured_image: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    is_published: Optional[bool] = None
    related_tops: Optional[List[str]] = None
    show_on_homepage: Optional[bool] = None

class BlogArticle(BlogArticleBase):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    views: int = 0

class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

# ==================== NEWSLETTER MODEL ====================

class NewsletterSubscription(BaseModel):
    email: str
    source: str = "website"
    subscribed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

class NewsletterSubscribe(BaseModel):
    email: str
    source: str = "website"


# ==================== HELPER FUNCTIONS ====================

def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[àáâãäå]', 'a', text)
    text = re.sub(r'[èéêë]', 'e', text)
    text = re.sub(r'[ìíîï]', 'i', text)
    text = re.sub(r'[òóôõö]', 'o', text)
    text = re.sub(r'[ùúûü]', 'u', text)
    text = re.sub(r'[ç]', 'c', text)
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text.strip('-')


# ==================== ARTICLE ENDPOINTS ====================

@api_router.get("/articles", response_model=List[Article])
async def get_articles(
    response: Response,
    category: Optional[str] = None,
    featured: Optional[bool] = None,
    limit: int = Query(default=20, le=100),
    admin: Optional[bool] = None
):
    now = datetime.now(timezone.utc)
    query = {}
    if category:
        query["category"] = category
    if featured is not None:
        query["is_featured"] = featured
    
    # Mode admin : retourner tous les articles (publiés + brouillons)
    # Mode public : seulement les publiés et dont la date de publication est passée
    if not admin:
        query["is_published"] = True
        query["$or"] = [
            {"scheduled_at": {"$exists": False}},
            {"scheduled_at": None},
            {"scheduled_at": {"$lte": now.isoformat()}}
        ]
    
    articles = await db.articles.find(query, {"_id": 0}).sort("created_at", -1).limit(limit).to_list(limit)
    
    for article in articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    # Cache 60s côté CDN/navigateur — les articles changent peu souvent
    response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"
    return articles

@api_router.get("/articles/featured", response_model=Optional[Article])
async def get_featured_article(response: Response):
    """Get the featured article - returns null if none is featured"""
    # Add no-cache headers to ensure fresh data
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    # STRICT: Only return article if is_featured is explicitly TRUE
    article = await db.articles.find_one({"is_featured": True}, {"_id": 0})
    if article and article.get("is_featured") == True:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
        return article
    return None

@api_router.get("/articles/top-of-month")
async def get_top_of_month_articles(response: Response):
    """Get articles marked as Top of the Month"""
    # Add no-cache headers
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    # STRICT: Only return articles where is_top_of_month is explicitly TRUE
    articles = await db.articles.find(
        {"is_top_of_month": True}, 
        {"_id": 0}
    ).sort("updated_at", -1).to_list(10)
    
    for article in articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    return articles

@api_router.get("/homepage/content")
async def get_homepage_content():
    """Get all content marked for homepage display"""
    # Get Top 10 articles marked for homepage
    top10_articles = await db.articles.find(
        {"show_on_homepage": True}, 
        {"_id": 0}
    ).sort("updated_at", -1).to_list(20)
    
    for article in top10_articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    # Get Blog articles marked for homepage
    blog_articles = await db.blog_posts.find(
        {"show_on_homepage": True, "is_published": True}, 
        {"_id": 0}
    ).sort("updated_at", -1).to_list(10)
    
    for article in blog_articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    return {
        "top10": top10_articles,
        "blog": blog_articles
    }

@api_router.get("/articles/search")
async def search_articles(q: str = Query(..., min_length=2)):
    now = datetime.now(timezone.utc).isoformat()
    regex_pattern = {"$regex": q, "$options": "i"}
    
    # Recherche dans les classements TOP
    top_query = {
        "$or": [
            {"title": regex_pattern},
            {"introduction": regex_pattern},
            {"category": regex_pattern}
        ]
    }
    articles = await db.articles.find(top_query, {"_id": 0}).limit(10).to_list(10)
    for article in articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
        article['_type'] = 'top'
    
    # Recherche dans les articles blog (publiés uniquement)
    blog_query = {
        "is_published": True,
        "$or": [
            {"scheduled_at": {"$exists": False}},
            {"scheduled_at": None},
            {"scheduled_at": {"$lte": now}}
        ],
        "$or": [
            {"title": regex_pattern},
            {"excerpt": regex_pattern},
            {"category": regex_pattern},
            {"tags": regex_pattern}
        ]
    }
    blog_articles = await db.blog_articles.find(blog_query, {"_id": 0}).limit(10).to_list(10)
    for article in blog_articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
        article['_type'] = 'blog'
    
    return {"tops": articles, "blog": blog_articles}

@api_router.get("/articles/category/{category}", response_model=List[Article])
async def get_articles_by_category(category: str):
    articles = await db.articles.find({"category": category}, {"_id": 0}).sort("created_at", -1).to_list(50)
    
    for article in articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    return articles

@api_router.get("/articles/{slug}", response_model=Article)
async def get_article(slug: str):
    article = await db.articles.find_one({"slug": slug}, {"_id": 0})
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Increment view count
    await db.articles.update_one({"slug": slug}, {"$inc": {"views": 1}})
    
    if isinstance(article.get('created_at'), str):
        article['created_at'] = datetime.fromisoformat(article['created_at'])
    if isinstance(article.get('updated_at'), str):
        article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    return article

@api_router.post("/articles", response_model=Article)
async def create_article(article_data: ArticleCreate, authenticated: bool = Depends(verify_token)):
    # Check if slug already exists
    existing = await db.articles.find_one({"slug": article_data.slug})
    if existing:
        raise HTTPException(status_code=400, detail="An article with this slug already exists")
    
    # If this article is featured, unfeatured others
    if article_data.is_featured:
        await db.articles.update_many({}, {"$set": {"is_featured": False}})
    
    article = Article(**article_data.model_dump())
    doc = article.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.articles.insert_one(doc)
    
    # Return without _id
    result = await db.articles.find_one({"id": article.id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    if isinstance(result.get('updated_at'), str):
        result['updated_at'] = datetime.fromisoformat(result['updated_at'])
    
    return result

@api_router.put("/articles/{article_id}", response_model=Article)
async def update_article(article_id: str, article_data: ArticleUpdate, authenticated: bool = Depends(verify_token)):
    existing = await db.articles.find_one({"id": article_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Include all non-None values (including False for booleans)
    update_data = {}
    for k, v in article_data.model_dump().items():
        if v is not None:
            update_data[k] = v
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    # If setting this as featured, unfeatured others
    if update_data.get("is_featured") == True:
        await db.articles.update_many({"id": {"$ne": article_id}}, {"$set": {"is_featured": False}})
    
    # Convert rankings to dict if present
    if "rankings" in update_data:
        update_data["rankings"] = [r.model_dump() if hasattr(r, 'model_dump') else r for r in update_data["rankings"]]
    
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.articles.update_one({"id": article_id}, {"$set": update_data})
    
    result = await db.articles.find_one({"id": article_id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    if isinstance(result.get('updated_at'), str):
        result['updated_at'] = datetime.fromisoformat(result['updated_at'])
    
    return result

@api_router.delete("/articles/{article_id}")
async def delete_article(article_id: str, authenticated: bool = Depends(verify_token)):
    result = await db.articles.delete_one({"id": article_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"message": "Article deleted successfully"}


# ==================== CATEGORIES ====================

@api_router.get("/categories", response_model=List[Category])
async def get_categories(response: Response):
    """Get all categories from database"""
    categories = await db.categories.find({}, {"_id": 0}).sort("order", 1).to_list(100)
    
    # If no categories exist, seed default ones
    if not categories:
        await seed_default_categories()
        categories = await db.categories.find({}, {"_id": 0}).sort("order", 1).to_list(100)
    
    for cat in categories:
        if isinstance(cat.get('created_at'), str):
            cat['created_at'] = datetime.fromisoformat(cat['created_at'])
    
    # Cache 5min — les catégories changent très rarement
    response.headers["Cache-Control"] = "public, max-age=300, stale-while-revalidate=3600"
    return categories

@api_router.post("/categories", response_model=Category)
async def create_category(category_data: CategoryCreate, authenticated: bool = Depends(verify_token)):
    """Create a new category"""
    # Check if slug already exists
    existing = await db.categories.find_one({"slug": category_data.slug})
    if existing:
        raise HTTPException(status_code=400, detail="Une catégorie avec ce slug existe déjà")
    
    category = Category(**category_data.model_dump())
    doc = category.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.categories.insert_one(doc)
    
    result = await db.categories.find_one({"id": category.id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    
    return result

@api_router.put("/categories/{category_id}", response_model=Category)
async def update_category(category_id: str, category_data: CategoryUpdate, authenticated: bool = Depends(verify_token)):
    """Update a category"""
    existing = await db.categories.find_one({"id": category_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Catégorie non trouvée")
    
    update_data = {k: v for k, v in category_data.model_dump().items() if v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="Aucune donnée à mettre à jour")
    
    await db.categories.update_one({"id": category_id}, {"$set": update_data})
    
    result = await db.categories.find_one({"id": category_id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    
    return result

@api_router.delete("/categories/{category_id}")
async def delete_category(category_id: str, authenticated: bool = Depends(verify_token)):
    """Delete a category"""
    # Check if category has articles
    category = await db.categories.find_one({"id": category_id})
    if not category:
        raise HTTPException(status_code=404, detail="Catégorie non trouvée")
    
    article_count = await db.articles.count_documents({"category": category["slug"]})
    if article_count > 0:
        raise HTTPException(
            status_code=400, 
            detail=f"Impossible de supprimer: {article_count} article(s) utilisent cette catégorie"
        )
    
    result = await db.categories.delete_one({"id": category_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Catégorie non trouvée")
    
    return {"message": "Catégorie supprimée avec succès"}

async def seed_default_categories():
    """Seed default categories if none exist"""
    default_categories = [
        {
            "id": str(uuid.uuid4()),
            "name": "Électronique",
            "slug": "electronique",
            "description": "Smartphones, ordinateurs, casques audio et gadgets tech",
            "icon": "cpu",
            "color": "blue",
            "order": 1,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Divertissement",
            "slug": "divertissement",
            "description": "Films, séries, jeux vidéo et musique",
            "icon": "film",
            "color": "purple",
            "order": 2,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Sport",
            "slug": "sport",
            "description": "Athlètes, équipes et événements sportifs",
            "icon": "trophy",
            "color": "green",
            "order": 3,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Lifestyle",
            "slug": "lifestyle",
            "description": "Voyage, mode, bien-être et tendances",
            "icon": "sparkles",
            "color": "amber",
            "order": 4,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    await db.categories.insert_many(default_categories)


# ==================== BLOG CATEGORIES ====================

@api_router.get("/blog/categories", response_model=List[BlogCategory])
async def get_blog_categories():
    """Get all blog categories"""
    categories = await db.blog_categories.find({}, {"_id": 0}).to_list(100)
    
    # If no categories exist, seed defaults
    if not categories:
        await seed_default_blog_categories()
        categories = await db.blog_categories.find({}, {"_id": 0}).to_list(100)
    
    for cat in categories:
        if isinstance(cat.get('created_at'), str):
            cat['created_at'] = datetime.fromisoformat(cat['created_at'])
    
    return categories

@api_router.post("/blog/categories", response_model=BlogCategory)
async def create_blog_category(data: BlogCategoryCreate, authenticated: bool = Depends(verify_token)):
    """Create a new blog category"""
    existing = await db.blog_categories.find_one({"slug": data.slug})
    if existing:
        raise HTTPException(status_code=400, detail="Une catégorie blog avec ce slug existe déjà")
    
    category = BlogCategory(**data.model_dump())
    doc = category.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.blog_categories.insert_one(doc)
    
    result = await db.blog_categories.find_one({"id": category.id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    
    return result

@api_router.delete("/blog/categories/{category_id}")
async def delete_blog_category(category_id: str, authenticated: bool = Depends(verify_token)):
    """Delete a blog category"""
    result = await db.blog_categories.delete_one({"id": category_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Catégorie non trouvée")
    return {"message": "Catégorie supprimée"}

async def seed_default_blog_categories():
    """Seed default blog categories"""
    defaults = [
        {"id": str(uuid.uuid4()), "name": "Actualités", "slug": "actualites", "description": "News et dernières tendances", "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": str(uuid.uuid4()), "name": "Guides", "slug": "guides", "description": "Guides d'achat et conseils", "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": str(uuid.uuid4()), "name": "Tests", "slug": "tests", "description": "Tests et avis détaillés", "created_at": datetime.now(timezone.utc).isoformat()},
        {"id": str(uuid.uuid4()), "name": "Comparatifs", "slug": "comparatifs", "description": "Comparaisons de produits", "created_at": datetime.now(timezone.utc).isoformat()},
    ]
    await db.blog_categories.insert_many(defaults)


# ==================== BLOG ARTICLES ====================

@api_router.get("/blog/articles")
async def get_blog_articles(
    category: Optional[str] = None,
    limit: int = Query(default=20, le=100),
    offset: int = 0,
    admin: Optional[bool] = None
):
    """Get all blog articles"""
    now = datetime.now(timezone.utc).isoformat()
    if admin:
        # Mode admin : tous les articles
        query = {}
    else:
        # Mode public : uniquement publiés et date passée
        query = {
            "is_published": True,
            "$or": [
                {"scheduled_at": {"$exists": False}},
                {"scheduled_at": None},
                {"scheduled_at": {"$lte": now}}
            ]
        }
    if category:
        query["category"] = category
    
    articles = await db.blog_articles.find(query, {"_id": 0}).sort("created_at", -1).skip(offset).limit(limit).to_list(limit)
    
    for article in articles:
        if isinstance(article.get('created_at'), str):
            article['created_at'] = datetime.fromisoformat(article['created_at'])
        if isinstance(article.get('updated_at'), str):
            article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    return articles

@api_router.get("/blog/articles/{slug}")
async def get_blog_article(slug: str):
    """Get a single blog article by slug"""
    article = await db.blog_articles.find_one({"slug": slug}, {"_id": 0})
    if not article:
        raise HTTPException(status_code=404, detail="Article non trouvé")
    
    # Increment views
    await db.blog_articles.update_one({"slug": slug}, {"$inc": {"views": 1}})
    
    if isinstance(article.get('created_at'), str):
        article['created_at'] = datetime.fromisoformat(article['created_at'])
    if isinstance(article.get('updated_at'), str):
        article['updated_at'] = datetime.fromisoformat(article['updated_at'])
    
    return article

@api_router.post("/blog/articles", response_model=BlogArticle)
async def create_blog_article(data: BlogArticleCreate, authenticated: bool = Depends(verify_token)):
    """Create a new blog article"""
    existing = await db.blog_articles.find_one({"slug": data.slug})
    if existing:
        raise HTTPException(status_code=400, detail="Un article avec ce slug existe déjà")
    
    article = BlogArticle(**data.model_dump())
    doc = article.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.blog_articles.insert_one(doc)
    
    result = await db.blog_articles.find_one({"id": article.id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    if isinstance(result.get('updated_at'), str):
        result['updated_at'] = datetime.fromisoformat(result['updated_at'])
    
    return result

@api_router.put("/blog/articles/{article_id}", response_model=BlogArticle)
async def update_blog_article(article_id: str, data: BlogArticleUpdate, authenticated: bool = Depends(verify_token)):
    """Update a blog article"""
    existing = await db.blog_articles.find_one({"id": article_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Article non trouvé")
    
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="Aucune donnée à mettre à jour")
    
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.blog_articles.update_one({"id": article_id}, {"$set": update_data})
    
    result = await db.blog_articles.find_one({"id": article_id}, {"_id": 0})
    if isinstance(result.get('created_at'), str):
        result['created_at'] = datetime.fromisoformat(result['created_at'])
    if isinstance(result.get('updated_at'), str):
        result['updated_at'] = datetime.fromisoformat(result['updated_at'])
    
    return result

@api_router.delete("/blog/articles/{article_id}")
async def delete_blog_article(article_id: str, authenticated: bool = Depends(verify_token)):
    """Delete a blog article"""
    result = await db.blog_articles.delete_one({"id": article_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Article non trouvé")
    return {"message": "Article supprimé"}

@api_router.get("/blog/popular-tops")
async def get_popular_tops(limit: int = 5):
    """Get most popular Top 10 articles for sidebar"""
    articles = await db.articles.find({}, {"_id": 0, "id": 1, "title": 1, "slug": 1, "image_url": 1, "views": 1, "category": 1}).sort("views", -1).limit(limit).to_list(limit)
    return articles


# ==================== NEWSLETTER ====================

@api_router.post("/newsletter/subscribe")
async def subscribe_newsletter(data: NewsletterSubscribe, request: Request):
    check_rate_limit(request, max_requests=3, window_seconds=300)
    """Subscribe to newsletter"""
    # Validate email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, data.email):
        raise HTTPException(status_code=400, detail="Email invalide")
    
    # Check if already subscribed
    existing = await db.newsletter.find_one({"email": data.email.lower()})
    if existing:
        if existing.get("is_active"):
            return {"message": "Vous êtes déjà inscrit à la newsletter", "already_subscribed": True}
        else:
            # Reactivate subscription
            await db.newsletter.update_one(
                {"email": data.email.lower()}, 
                {"$set": {"is_active": True, "subscribed_at": datetime.now(timezone.utc).isoformat()}}
            )
            return {"message": "Votre inscription a été réactivée", "reactivated": True}
    
    # Create new subscription
    subscription = {
        "email": data.email.lower(),
        "source": data.source,
        "subscribed_at": datetime.now(timezone.utc).isoformat(),
        "is_active": True
    }
    await db.newsletter.insert_one(subscription)

    # Email de bienvenue via Brevo
    welcome_html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #050505; color: #ffffff; padding: 40px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #ffffff; font-size: 28px;">THE<span style="color: #0057FF;">CLASSEMENT</span></h1>
      </div>
      <h2 style="color: #ffffff;">Bienvenue dans la communauté ! 🎉</h2>
      <p style="color: #A1A1AA; line-height: 1.6;">
        Merci de vous être inscrit à la newsletter de TheClassement.<br>
        Vous recevrez nos meilleurs classements et TOP 10 directement dans votre boîte mail.
      </p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="https://theclassement.com" style="background: #0057FF; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">
          Découvrir les classements →
        </a>
      </div>
      <p style="color: #71717A; font-size: 12px; text-align: center;">
        Pour vous désinscrire, <a href="https://theclassement.com/unsubscribe?email={data.email.lower()}" style="color: #0057FF;">cliquez ici</a>
      </p>
    </div>
    """
    await send_brevo_email(data.email.lower(), data.email.lower(), "Bienvenue sur TheClassement ! 🎉", welcome_html)
    
    return {"message": "Inscription réussie ! Merci de votre intérêt.", "success": True}

@api_router.get("/newsletter/subscribers")
async def get_newsletter_subscribers(authenticated: bool = Depends(verify_token)):
    """Get all newsletter subscribers (admin only)"""
    subscribers = await db.newsletter.find({"is_active": True}, {"_id": 0}).to_list(1000)
    return {"count": len(subscribers), "subscribers": subscribers}

@api_router.post("/newsletter/unsubscribe")
async def unsubscribe_newsletter(email: str):
    """Unsubscribe from newsletter"""
    result = await db.newsletter.update_one(
        {"email": email.lower()},
        {"$set": {"is_active": False}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Email non trouvé")
    return {"message": "Désinscription effectuée"}

class NewsletterSend(BaseModel):
    subject: str
    html_content: str

@api_router.post("/newsletter/send")
async def send_newsletter(data: NewsletterSend, authenticated: bool = Depends(verify_token)):
    """Envoyer une newsletter à tous les abonnés actifs (admin only)"""
    result = await send_newsletter_to_all(data.subject, data.html_content)
    return result

@api_router.post("/newsletter/send-article/{article_id}")
async def send_article_newsletter(article_id: str, authenticated: bool = Depends(verify_token)):
    """Envoyer un email automatique quand un article est publié"""
    article = await db.articles.find_one({"id": article_id}, {"_id": 0})
    if not article:
        raise HTTPException(status_code=404, detail="Article non trouvé")
    
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #050505; color: #ffffff; padding: 40px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #ffffff; font-size: 28px;">THE<span style="color: #0057FF;">CLASSEMENT</span></h1>
      </div>
      <h2 style="color: #ffffff;">Nouveau classement : {article.get('title', '')}</h2>
      <p style="color: #A1A1AA; line-height: 1.6;">{article.get('excerpt', '')}</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="https://theclassement.com/article/{article.get('slug', '')}" 
           style="background: #0057FF; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">
          Voir le classement →
        </a>
      </div>
      <p style="color: #71717A; font-size: 12px; text-align: center;">
        Pour vous désinscrire, <a href="https://theclassement.com/unsubscribe" style="color: #0057FF;">cliquez ici</a>
      </p>
    </div>
    """
    subject = f"Nouveau TOP 10 : {article.get('title', '')}"
    result = await send_newsletter_to_all(subject, html)
    return result


# ==================== IMAGE UPLOAD ====================

@api_router.post("/upload/image")
async def upload_image(file: UploadFile = File(...), authenticated: bool = Depends(verify_token)):
    """Upload an image file"""
    # Validate file type
    allowed_types = ["image/jpeg", "image/png", "image/webp", "image/gif"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Type de fichier non autorisé. Utilisez JPG, PNG, WebP ou GIF.")
    
    # Validate file size (max 5MB)
    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Fichier trop volumineux (max 5MB)")
    
    # Generate unique filename
    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    filename = f"{uuid.uuid4()}.{ext}"
    filepath = UPLOAD_DIR / filename
    
    # Compression avec Pillow si disponible
    original_size = len(contents)
    if PIL_AVAILABLE and file.content_type in ["image/jpeg", "image/png", "image/webp"]:
        try:
            img = Image.open(io.BytesIO(contents))
            # Redimensionner si trop grande (max 1200px de large)
            if img.width > 1200:
                ratio = 1200 / img.width
                new_height = int(img.height * ratio)
                img = img.resize((1200, new_height), Image.LANCZOS)
            # Convertir en WebP pour meilleure compression
            filename = f"{uuid.uuid4()}.webp"
            filepath = UPLOAD_DIR / filename
            output = io.BytesIO()
            img.convert("RGB").save(output, format="WEBP", quality=82, optimize=True)
            contents = output.getvalue()
        except Exception as e:
            logger.warning(f"Compression échouée, sauvegarde originale: {e}")

    # Save file
    with open(filepath, "wb") as f:
        f.write(contents)
    
    return {
        "success": True,
        "filename": filename,
        "url": f"/api/uploads/{filename}",
        "size": len(contents),
        "original_size": original_size,
        "compressed": PIL_AVAILABLE
    }

@api_router.get("/uploads/{filename}")
async def get_uploaded_image(filename: str):
    """Serve uploaded image"""
    filepath = UPLOAD_DIR / filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Image non trouvée")
    
    # Determine content type
    ext = filename.split(".")[-1].lower()
    content_types = {
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "webp": "image/webp",
        "gif": "image/gif"
    }
    content_type = content_types.get(ext, "application/octet-stream")
    
    with open(filepath, "rb") as f:
        content = f.read()
    
    return Response(content=content, media_type=content_type)


# ==================== ANALYTICS/STATS ====================

@api_router.get("/stats/overview")
async def get_stats_overview(authenticated: bool = Depends(verify_token)):
    """Get site statistics overview (admin only)"""
    articles_count = await db.articles.count_documents({})
    blog_count = await db.blog_articles.count_documents({})
    newsletter_count = await db.newsletter.count_documents({"is_active": True})
    
    # Total views
    pipeline = [{"$group": {"_id": None, "total": {"$sum": "$views"}}}]
    article_views = await db.articles.aggregate(pipeline).to_list(1)
    blog_views = await db.blog_articles.aggregate(pipeline).to_list(1)
    
    total_views = (article_views[0]["total"] if article_views else 0) + (blog_views[0]["total"] if blog_views else 0)
    
    # Top articles
    top_articles = await db.articles.find({}, {"_id": 0, "title": 1, "slug": 1, "views": 1}).sort("views", -1).limit(5).to_list(5)
    
    return {
        "articles_count": articles_count,
        "blog_count": blog_count,
        "newsletter_subscribers": newsletter_count,
        "total_views": total_views,
        "top_articles": top_articles
    }


# ==================== SEED DATA ====================

@api_router.post("/seed")
async def seed_database():
    # Check if data already exists
    count = await db.articles.count_documents({})
    if count > 0:
        # Don't auto-set featured - let user decide
        return {"message": f"Database already has {count} articles"}
    
    seed_articles = [
        {
            "id": str(uuid.uuid4()),
            "title": "Top 10 des Smartphones 2025",
            "slug": "top-10-smartphones-2025",
            "image_url": "https://images.pexels.com/photos/6498776/pexels-photo-6498776.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
            "introduction": "Découvrez notre sélection des meilleurs smartphones de 2025. De l'iPhone 16 Pro Max au Samsung Galaxy S25 Ultra, voici les appareils qui ont marqué cette année par leur innovation et leurs performances exceptionnelles.",
            "category": "electronique",
            "is_featured": True,
            "views": 1250,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": [
                {"rank": 10, "title": "Google Pixel 9", "description": "L'intelligence artificielle au service de la photo. Le Pixel 9 excelle avec ses fonctionnalités IA exclusives.", "link_url": "https://store.google.com/product/pixel_9", "link_text": "Voir sur Google Store"},
                {"rank": 9, "title": "OnePlus 13", "description": "Le flagship killer par excellence. Performances haut de gamme à prix compétitif.", "link_url": None, "link_text": None},
                {"rank": 8, "title": "Xiaomi 15 Pro", "description": "Un rapport qualité-prix imbattable avec un appareil photo Leica.", "link_url": None, "link_text": None},
                {"rank": 7, "title": "Sony Xperia 1 VI", "description": "L'écran 4K OLED qui fait la différence pour les créateurs de contenu.", "link_url": None, "link_text": None},
                {"rank": 6, "title": "Huawei Mate 60 Pro", "description": "Le retour en force avec des innovations technologiques majeures.", "link_url": None, "link_text": None},
                {"rank": 5, "title": "Oppo Find X8 Pro", "description": "Design élégant et charge rapide révolutionnaire.", "link_url": None, "link_text": None},
                {"rank": 4, "title": "iPhone 16", "description": "L'équilibre parfait entre prix et fonctionnalités premium.", "link_url": "https://www.apple.com/fr/iphone-16/", "link_text": "Découvrir sur Apple"},
                {"rank": 3, "title": "Samsung Galaxy S25+", "description": "L'alternative Android parfaite avec Galaxy AI intégré.", "link_url": None, "link_text": None},
                {"rank": 2, "title": "Samsung Galaxy S25 Ultra", "description": "Le stylet S Pen et un zoom 200x pour les professionnels exigeants.", "link_url": "https://www.samsung.com/fr/smartphones/galaxy-s25-ultra/", "link_text": "Voir sur Samsung"},
                {"rank": 1, "title": "iPhone 16 Pro Max", "description": "La référence absolue. Puce A18 Pro, Action Button, et le meilleur écosystème mobile.", "link_url": "https://www.apple.com/fr/shop/buy-iphone/iphone-16-pro", "link_text": "Acheter sur Apple"}
            ]
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Top 10 des Films de 2024",
            "slug": "top-10-films-2024",
            "image_url": "https://images.unsplash.com/photo-1489599849927-2ee91cede3ba?crop=entropy&cs=srgb&fm=jpg&q=85",
            "introduction": "Une année cinématographique exceptionnelle ! Des blockbusters aux films d'auteur, voici notre classement des 10 films qui ont marqué 2024.",
            "category": "divertissement",
            "is_featured": False,
            "views": 890,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": [
                {"rank": 10, "title": "Civil War", "description": "Alex Garland nous offre une vision saisissante d'une Amérique divisée.", "link_url": None, "link_text": None},
                {"rank": 9, "title": "Furiosa: A Mad Max Saga", "description": "Le prequel tant attendu qui explore les origines de l'héroïne culte.", "link_url": None, "link_text": None},
                {"rank": 8, "title": "Challengers", "description": "Luca Guadagnino signe un thriller sportif électrisant avec Zendaya.", "link_url": None, "link_text": None},
                {"rank": 7, "title": "Alien: Romulus", "description": "Le retour aux sources de la franchise avec une terreur viscérale.", "link_url": None, "link_text": None},
                {"rank": 6, "title": "Inside Out 2", "description": "Pixar frappe fort avec cette suite émouvante sur l'adolescence.", "link_url": None, "link_text": None},
                {"rank": 5, "title": "Gladiator II", "description": "Ridley Scott revient à Rome avec une épopée grandiose.", "link_url": None, "link_text": None},
                {"rank": 4, "title": "The Brutalist", "description": "Brady Corbet livre une fresque architecturale de 3h30 magistrale.", "link_url": None, "link_text": None},
                {"rank": 3, "title": "Anora", "description": "Sean Baker capture l'Amérique contemporaine avec brio.", "link_url": None, "link_text": None},
                {"rank": 2, "title": "Oppenheimer", "description": "Christopher Nolan continue de dominer avec ce chef-d'œuvre historique.", "link_url": "https://www.imdb.com/title/tt15398776/", "link_text": "Voir sur IMDB"},
                {"rank": 1, "title": "Dune: Part Two", "description": "Denis Villeneuve complète son adaptation épique avec un film visuellement stupéfiant.", "link_url": "https://www.imdb.com/title/tt15239678/", "link_text": "Voir sur IMDB"}
            ]
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Top 10 des Sportifs de l'Année",
            "slug": "top-10-sportifs-annee",
            "image_url": "https://images.pexels.com/photos/14585533/pexels-photo-14585533.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940",
            "introduction": "Des Jeux Olympiques de Paris aux compétitions mondiales, ces athlètes ont dominé leur discipline et inspiré des millions de fans à travers le monde.",
            "category": "sport",
            "is_featured": False,
            "views": 2100,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": [
                {"rank": 10, "title": "Max Verstappen", "description": "Quadruple champion du monde de F1, une domination sans partage.", "link_url": None, "link_text": None},
                {"rank": 9, "title": "Simone Biles", "description": "La GOAT de la gymnastique continue de repousser les limites.", "link_url": None, "link_text": None},
                {"rank": 8, "title": "Novak Djokovic", "description": "L'or olympique, la pièce manquante à sa collection légendaire.", "link_url": None, "link_text": None},
                {"rank": 7, "title": "Armand Duplantis", "description": "Le Suédois volant bat encore son propre record du monde.", "link_url": None, "link_text": None},
                {"rank": 6, "title": "Erling Haaland", "description": "La machine à buts de Manchester City continue d'affoler les compteurs.", "link_url": None, "link_text": None},
                {"rank": 5, "title": "Kylian Mbappé", "description": "Le nouveau galactique du Real Madrid.", "link_url": "https://www.realmadrid.com/", "link_text": "Real Madrid Official"},
                {"rank": 4, "title": "Vinicius Jr", "description": "Le Ballon d'Or 2024 qui fait danser les défenseurs.", "link_url": None, "link_text": None},
                {"rank": 3, "title": "Carlos Alcaraz", "description": "Le prodige espagnol rafle Wimbledon et Roland-Garros.", "link_url": None, "link_text": None},
                {"rank": 2, "title": "Léon Marchand", "description": "Le héros français des JO de Paris avec 4 médailles d'or.", "link_url": None, "link_text": None},
                {"rank": 1, "title": "LeBron James", "description": "À 39 ans, il mène Team USA à l'or olympique. La légende continue.", "link_url": "https://www.nba.com/player/2544/lebron-james", "link_text": "Profil NBA"}
            ]
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Top 10 des Destinations Voyage 2025",
            "slug": "top-10-destinations-voyage-2025",
            "image_url": "https://images.unsplash.com/photo-1507525428034-b723cf961d3e?crop=entropy&cs=srgb&fm=jpg&q=85",
            "introduction": "Envie d'évasion ? Voici les destinations qui feront rêver les voyageurs cette année, entre trésors cachés et incontournables revisités.",
            "category": "lifestyle",
            "is_featured": False,
            "views": 756,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": [
                {"rank": 10, "title": "Dubaï, Émirats", "description": "Entre luxe et démesure, la ville du futur ne cesse de se réinventer.", "link_url": None, "link_text": None},
                {"rank": 9, "title": "Bali, Indonésie", "description": "L'île des dieux reste une valeur sûre pour le wellness et la spiritualité.", "link_url": None, "link_text": None},
                {"rank": 8, "title": "Islande", "description": "Aurores boréales et paysages lunaires pour les aventuriers.", "link_url": None, "link_text": None},
                {"rank": 7, "title": "Costa Rica", "description": "L'écotourisme à son apogée dans ce paradis de biodiversité.", "link_url": None, "link_text": None},
                {"rank": 6, "title": "Grèce", "description": "Santorin, Mykonos et les Cyclades n'ont jamais été aussi tendance.", "link_url": None, "link_text": None},
                {"rank": 5, "title": "Nouvelle-Zélande", "description": "L'aventure au bout du monde, entre fjords et volcans.", "link_url": None, "link_text": None},
                {"rank": 4, "title": "Portugal", "description": "Lisbonne, Porto et l'Algarve : le charme européen accessible.", "link_url": None, "link_text": None},
                {"rank": 3, "title": "Norvège", "description": "Les fjords norvégiens, une expérience nature inoubliable.", "link_url": None, "link_text": None},
                {"rank": 2, "title": "Japon", "description": "Tradition et modernité dans un équilibre parfait.", "link_url": "https://www.japan.travel/fr/", "link_text": "Japan Travel"},
                {"rank": 1, "title": "Italie", "description": "Rome, Florence, la côte amalfitaine... L'Italie reste indétrônable.", "link_url": None, "link_text": None}
            ]
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Top 10 des Séries Netflix 2024",
            "slug": "top-10-series-netflix-2024",
            "image_url": "https://images.unsplash.com/photo-1522869635100-9f4c5e86aa37?crop=entropy&cs=srgb&fm=jpg&q=85",
            "introduction": "Netflix continue de dominer le streaming avec des productions originales captivantes. Voici les séries qui ont fait le buzz cette année.",
            "category": "divertissement",
            "is_featured": False,
            "views": 1580,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": [
                {"rank": 10, "title": "The Gentlemen", "description": "Guy Ritchie adapte son film en série avec le charme britannique habituel.", "link_url": None, "link_text": None},
                {"rank": 9, "title": "3 Body Problem", "description": "La SF ambitieuse des créateurs de Game of Thrones.", "link_url": None, "link_text": None},
                {"rank": 8, "title": "Baby Reindeer", "description": "Le phénomène autobiographique qui a bouleversé les audiences.", "link_url": None, "link_text": None},
                {"rank": 7, "title": "Fallout", "description": "L'adaptation du jeu vidéo qui a conquis fans et néophytes.", "link_url": None, "link_text": None},
                {"rank": 6, "title": "Ripley", "description": "Andrew Scott dans une version noir et blanc sublime.", "link_url": None, "link_text": None},
                {"rank": 5, "title": "Shogun", "description": "L'épopée japonaise qui redéfinit les standards de production.", "link_url": None, "link_text": None},
                {"rank": 4, "title": "The Bear (Saison 3)", "description": "La cuisine comme vous ne l'avez jamais vue.", "link_url": None, "link_text": None},
                {"rank": 3, "title": "House of the Dragon (S2)", "description": "Les Targaryen continuent leur guerre civile épique.", "link_url": None, "link_text": None},
                {"rank": 2, "title": "Arcane (Saison 2)", "description": "L'animation atteint des sommets avec cette conclusion magistrale.", "link_url": "https://www.netflix.com/title/81435684", "link_text": "Voir sur Netflix"},
                {"rank": 1, "title": "Squid Game (Saison 2)", "description": "Le retour du phénomène mondial qui a battu tous les records.", "link_url": "https://www.netflix.com/title/81040344", "link_text": "Voir sur Netflix"}
            ]
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Top 10 des Casques Audio 2025",
            "slug": "top-10-casques-audio-2025",
            "image_url": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?crop=entropy&cs=srgb&fm=jpg&q=85",
            "introduction": "Audiophiles et mélomanes, ce classement est pour vous ! Des casques haut de gamme aux meilleurs rapports qualité-prix, trouvez votre compagnon sonore idéal.",
            "category": "electronique",
            "is_featured": False,
            "views": 620,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": [
                {"rank": 10, "title": "Bose QuietComfort Ultra", "description": "La réduction de bruit légendaire dans un confort absolu.", "link_url": None, "link_text": None},
                {"rank": 9, "title": "Sennheiser Momentum 4", "description": "Le son signature Sennheiser pour les puristes.", "link_url": None, "link_text": None},
                {"rank": 8, "title": "Bang & Olufsen Beoplay H100", "description": "Le luxe danois au service de l'audio.", "link_url": None, "link_text": None},
                {"rank": 7, "title": "Focal Bathys", "description": "L'excellence française en Bluetooth.", "link_url": None, "link_text": None},
                {"rank": 6, "title": "Beyerdynamic DT 1990 Pro", "description": "La référence studio pour les professionnels.", "link_url": None, "link_text": None},
                {"rank": 5, "title": "Audeze Maxwell", "description": "Le gaming audiophile sans compromis.", "link_url": None, "link_text": None},
                {"rank": 4, "title": "Apple AirPods Max 2", "description": "L'écosystème Apple dans un casque premium.", "link_url": "https://www.apple.com/fr/airpods-max/", "link_text": "Voir sur Apple"},
                {"rank": 3, "title": "Sennheiser HD 800 S", "description": "La référence hi-fi pour les audiophiles exigeants.", "link_url": None, "link_text": None},
                {"rank": 2, "title": "Sony WH-1000XM6", "description": "L'équilibre parfait : ANC, son, autonomie.", "link_url": None, "link_text": None},
                {"rank": 1, "title": "Apple AirPods Pro 3", "description": "Les écouteurs qui ont changé l'industrie, maintenant avec audio spatial.", "link_url": "https://www.apple.com/fr/airpods-pro/", "link_text": "Voir sur Apple"}
            ]
        }
    ]
    
    await db.articles.insert_many(seed_articles)
    return {"message": f"Successfully seeded {len(seed_articles)} articles"}


# ==================== STATUS ENDPOINTS ====================

@api_router.get("/")
async def root():
    return {"message": "The Classement API is running"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks


# ==================== SEO: SITEMAP & PRERENDERING ====================

SITE_URL = "https://theclassement.com"

# List of bot user agents
BOT_USER_AGENTS = [
    'googlebot', 'bingbot', 'yandexbot', 'duckduckbot', 'slurp', 
    'baiduspider', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
    'whatsapp', 'telegram', 'pinterest', 'applebot', 'semrushbot'
]

def is_bot(user_agent: str) -> bool:
    if not user_agent:
        return False
    user_agent_lower = user_agent.lower()
    return any(bot in user_agent_lower for bot in BOT_USER_AGENTS)

# Sitemap under /api prefix to be accessible via ingress
@api_router.get("/sitemap.xml", response_class=Response)
async def sitemap():
    """Generate dynamic sitemap.xml"""
    articles = await db.articles.find({}, {"_id": 0, "slug": 1, "updated_at": 1, "category": 1}).to_list(1000)
    blog_articles = await db.blog_articles.find({"is_published": True}, {"_id": 0, "slug": 1, "updated_at": 1}).to_list(1000)
    categories = await db.categories.find({}, {"_id": 0, "slug": 1}).to_list(100)
    
    xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_content += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    
    # Homepage
    xml_content += f'''  <url>
    <loc>{SITE_URL}/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>\n'''
    
    # Blog page
    xml_content += f'''  <url>
    <loc>{SITE_URL}/blog</loc>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>\n'''
    
    # Dynamic Categories
    for cat in categories:
        xml_content += f'''  <url>
    <loc>{SITE_URL}/category/{cat['slug']}</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>\n'''
    
    # Top 10 Articles
    for article in articles:
        updated = article.get('updated_at', datetime.now(timezone.utc).isoformat())
        if isinstance(updated, datetime):
            updated = updated.strftime('%Y-%m-%d')
        else:
            updated = updated[:10] if len(updated) > 10 else updated
            
        xml_content += f'''  <url>
    <loc>{SITE_URL}/article/{article['slug']}</loc>
    <lastmod>{updated}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>\n'''
    
    # Blog Articles
    for blog in blog_articles:
        updated = blog.get('updated_at', datetime.now(timezone.utc).isoformat())
        if isinstance(updated, datetime):
            updated = updated.strftime('%Y-%m-%d')
        else:
            updated = updated[:10] if len(updated) > 10 else updated
            
        xml_content += f'''  <url>
    <loc>{SITE_URL}/blog/{blog['slug']}</loc>
    <lastmod>{updated}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>\n'''
    
    # Static pages
    static_pages = ['about', 'mentions-legales', 'confidentialite']
    for page in static_pages:
        xml_content += f'''  <url>
    <loc>{SITE_URL}/{page}</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>\n'''
    
    xml_content += '</urlset>'
    
    return Response(content=xml_content, media_type="application/xml")

# Prerendered pages for SEO bots - under /api prefix
@api_router.get("/prerender/article/{slug}", response_class=HTMLResponse)
async def prerender_article(slug: str, request: Request):
    """Serve pre-rendered HTML for bots"""
    article = await db.articles.find_one({"slug": slug}, {"_id": 0})
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Generate full HTML with all content
    rankings_html = ""
    for rank in sorted(article.get('rankings', []), key=lambda x: -x['rank']):
        rankings_html += f"""
        <article class="ranking-item" itemscope itemtype="https://schema.org/ListItem">
            <meta itemprop="position" content="{rank['rank']}">
            <h3 itemprop="name">{rank['rank']}. {rank['title']}</h3>
            <p itemprop="description">{rank['description']}</p>
            {f'<a href="{rank["link_url"]}" rel="nofollow">{rank.get("link_text", "Voir sur Amazon")}</a>' if rank.get('link_url') else ''}
        </article>
        """
    
    category_names = {
        'electronique': 'Électronique',
        'divertissement': 'Divertissement',
        'sport': 'Sport',
        'lifestyle': 'Lifestyle'
    }
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{article['title']} | The Classement</title>
    <meta name="description" content="{article['introduction'][:160]}">
    <meta name="keywords" content="top 10, classement, {category_names.get(article['category'], '')}, comparatif, meilleur">
    <link rel="canonical" href="{SITE_URL}/article/{slug}">
    
    <!-- Open Graph -->
    <meta property="og:type" content="article">
    <meta property="og:title" content="{article['title']}">
    <meta property="og:description" content="{article['introduction'][:200]}">
    <meta property="og:image" content="{article['image_url']}">
    <meta property="og:url" content="{SITE_URL}/article/{slug}">
    <meta property="og:site_name" content="The Classement">
    
    <!-- Twitter -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{article['title']}">
    <meta name="twitter:description" content="{article['introduction'][:200]}">
    <meta name="twitter:image" content="{article['image_url']}">
    
    <!-- Schema.org -->
    <script type="application/ld+json">
    {{
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": "{article['title']}",
        "description": "{article['introduction'][:200]}",
        "image": "{article['image_url']}",
        "author": {{
            "@type": "Organization",
            "name": "The Classement"
        }},
        "publisher": {{
            "@type": "Organization",
            "name": "The Classement",
            "url": "{SITE_URL}"
        }},
        "datePublished": "{article.get('created_at', '')}",
        "dateModified": "{article.get('updated_at', '')}",
        "mainEntityOfPage": "{SITE_URL}/article/{slug}"
    }}
    </script>
</head>
<body>
    <header>
        <nav>
            <a href="{SITE_URL}">The Classement</a>
            <a href="{SITE_URL}/category/electronique">Électronique</a>
            <a href="{SITE_URL}/category/divertissement">Divertissement</a>
            <a href="{SITE_URL}/about">À propos</a>
        </nav>
    </header>
    
    <main itemscope itemtype="https://schema.org/Article">
        <article>
            <header>
                <span class="category">{category_names.get(article['category'], article['category'])}</span>
                <h1 itemprop="headline">{article['title']}</h1>
                <img src="{article['image_url']}" alt="{article['title']}" itemprop="image">
            </header>
            
            <section itemprop="articleBody">
                <h2>Introduction</h2>
                <p itemprop="description">{article['introduction']}</p>
                
                <h2>Le Classement Complet</h2>
                <div itemscope itemtype="https://schema.org/ItemList">
                    <meta itemprop="numberOfItems" content="{len(article.get('rankings', []))}">
                    {rankings_html}
                </div>
            </section>
            
            <footer>
                <p>Publié le {article.get('created_at', '')[:10] if article.get('created_at') else ''}</p>
                <p>Vues: {article.get('views', 0)}</p>
            </footer>
        </article>
    </main>
    
    <footer>
        <p>© 2025 The Classement. Tous droits réservés.</p>
        <p>En tant que Partenaire Amazon, The Classement réalise un bénéfice sur les achats remplissant les conditions requises.</p>
        <nav>
            <a href="{SITE_URL}/mentions-legales">Mentions légales</a>
            <a href="{SITE_URL}/confidentialite">Politique de confidentialité</a>
        </nav>
    </footer>
</body>
</html>"""
    
    return HTMLResponse(content=html)


@api_router.get("/prerender/", response_class=HTMLResponse)
async def prerender_homepage(request: Request):
    """Serve pre-rendered HTML for homepage for bots"""
    articles = await db.articles.find({}, {"_id": 0}).sort("created_at", -1).limit(10).to_list(10)
    featured = await db.articles.find_one({"is_featured": True}, {"_id": 0})
    
    articles_html = ""
    for article in articles:
        articles_html += f"""
        <article itemscope itemtype="https://schema.org/Article">
            <a href="{SITE_URL}/article/{article['slug']}">
                <img src="{article['image_url']}" alt="{article['title']}" itemprop="image">
                <h3 itemprop="headline">{article['title']}</h3>
                <p itemprop="description">{article['introduction'][:150]}...</p>
            </a>
        </article>
        """
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Classement - Le TOP 10 de référence</title>
    <meta name="description" content="Votre source de référence pour les meilleurs classements et TOP 10 dans toutes les catégories : tech, cinéma, sport et lifestyle.">
    <meta name="keywords" content="top 10, classement, comparatif, meilleur, guide, test, avis">
    <link rel="canonical" href="{SITE_URL}/">
    
    <!-- Open Graph -->
    <meta property="og:type" content="website">
    <meta property="og:title" content="The Classement - Le TOP 10 de référence">
    <meta property="og:description" content="Découvrez les meilleurs classements et TOP 10 dans toutes les catégories.">
    <meta property="og:url" content="{SITE_URL}/">
    <meta property="og:site_name" content="The Classement">
    
    <!-- Schema.org -->
    <script type="application/ld+json">
    {{
        "@context": "https://schema.org",
        "@type": "WebSite",
        "name": "The Classement",
        "url": "{SITE_URL}",
        "description": "Votre source de référence pour les meilleurs classements et TOP 10",
        "potentialAction": {{
            "@type": "SearchAction",
            "target": "{SITE_URL}/search?q={{search_term_string}}",
            "query-input": "required name=search_term_string"
        }}
    }}
    </script>
</head>
<body>
    <header>
        <h1>The Classement - Le TOP 10 de référence</h1>
        <nav>
            <a href="{SITE_URL}/category/electronique">Électronique</a>
            <a href="{SITE_URL}/category/divertissement">Divertissement</a>
            <a href="{SITE_URL}/category/sport">Sport</a>
            <a href="{SITE_URL}/category/lifestyle">Lifestyle</a>
            <a href="{SITE_URL}/about">À propos</a>
        </nav>
    </header>
    
    <main>
        <section>
            <h2>Derniers Classements</h2>
            {articles_html}
        </section>
    </main>
    
    <footer>
        <p>© 2025 The Classement. Tous droits réservés.</p>
        <p>En tant que Partenaire Amazon, The Classement réalise un bénéfice sur les achats remplissant les conditions requises.</p>
    </footer>
</body>
</html>"""
    
    return HTMLResponse(content=html)

# Include the router in the main app AFTER all routes are defined
app.include_router(api_router)

# ═══════════════════════════════════════════════════════════════════════
# CORS — Solution permanente (plus jamais besoin de modifier ce fichier)
# ═══════════════════════════════════════════════════════════════════════
#
# ✅ theclassement.com → toujours autorisé (domaine permanent)
# ✅ *.hostingersite.com → autorisé via regex (TOUS les sous-domaines
#    générés par Hostinger, même les nouveaux, sans toucher ce fichier)
# ✅ CORS_ORIGINS → variable d'env pour cas exceptionnels
# ═══════════════════════════════════════════════════════════════════════

import re as _re
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as _CORSRequest
from starlette.responses import Response as _CORSResponse

_FIXED_ORIGINS = {
    "https://theclassement.com",
    "https://www.theclassement.com",
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "https://palevioletred-grasshopper-749161.hostingersite.com",
}

_ENV_ORIGINS = {
    o.strip()
    for o in os.environ.get("CORS_ORIGINS", "").split(",")
    if o.strip()
}

# Autorise TOUS les *.hostingersite.com automatiquement
_HOSTINGER_RE = _re.compile(r"^https://[a-z0-9][a-z0-9\-]*\.hostingersite\.com$")

def _cors_allowed(origin: str) -> bool:
    if not origin:
        return False
    if origin in _FIXED_ORIGINS or origin in _ENV_ORIGINS:
        return True
    if _HOSTINGER_RE.match(origin):
        return True
    return False

class SmartCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: _CORSRequest, call_next):
        origin = request.headers.get("origin", "")
        allowed = _cors_allowed(origin)
        if request.method == "OPTIONS":
            res = _CORSResponse(status_code=204)
            if allowed:
                res.headers["Access-Control-Allow-Origin"] = origin
                res.headers["Access-Control-Allow-Credentials"] = "true"
                res.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS,PATCH"
                res.headers["Access-Control-Allow-Headers"] = "*"
                res.headers["Access-Control-Max-Age"] = "86400"
            return res
        response = await call_next(request)
        if allowed:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Expose-Headers"] = "*"
        return response

app.add_middleware(SmartCORSMiddleware)

# ── Shutdown propre ───────────────────────────────────────────────────
import atexit as _atexit
_atexit.register(lambda: client.close())
