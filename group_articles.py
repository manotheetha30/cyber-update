"Stage - Group articles describing the same security incidents together"
from sentence_transformers import SentenceTransformer
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics.pairwise import cosine_similarity
from models import ExtractedArticle
# Load once when your application starts
model = SentenceTransformer("all-MiniLM-L6-v2")

def group_news(articles:list[ExtractedArticle],similarity_threshold=0.6):
    """
    Groups similar cybersecurity article titles.

    Args:
        titles (list[str]): List of article titles.
        similarity_threshold (float): Cosine similarity required for grouping.

    Returns:
        list[list[int]]: List of clusters containing title indices.
    """
    
    titles=[]
    for article in articles:
        titles.append(article.rss_article.title+"\n"+article.full_text[:80])
    
    if len(titles) == 0:
        return []

    if len(titles) == 1:
        return [[0]]

    # Generate embeddings
    embeddings = model.encode(
        titles,
        convert_to_numpy=True,
        normalize_embeddings=True
    )

    # Cosine similarity matrix
    similarity = cosine_similarity(embeddings)

    # Convert similarity to distance
    distance = 1 - similarity

    clustering = AgglomerativeClustering(
        metric="precomputed",
        linkage="average",
        distance_threshold=1 - similarity_threshold,
        n_clusters=None
    )

    labels = clustering.fit_predict(distance)

    clusters = {}

    for idx, label in enumerate(labels):
        clusters.setdefault(label, []).append(titles[idx])

    print(clusters)

