"Stage - Group articles describing the same security incidents together"
from sentence_transformers import SentenceTransformer
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics.pairwise import cosine_similarity
from models import ExtractedArticle
model = SentenceTransformer("BAAI/bge-small-en-v1.5")  

def group_news(articles:list[ExtractedArticle],similarity_threshold=0.85) -> list[list[int]]:
    """
    Groups similar cybersecurity article titles.

    Args:
        articles (list[ExtractedArticle]): List of extracted articles.
        similarity_threshold (float): Cosine similarity required for grouping.

    Returns:
        list[list[int]]: List of clusters containing article indices.
    """

    titles_content=[]
    for article in articles:

        titles_content.append(article.rss_article.title + " " + article.full_text[:500])
    
    if len(titles_content) == 0:
        return []

    if len(titles_content) == 1:
        return [[0]]

    # Generate embeddings
    embeddings = model.encode(titles_content,convert_to_numpy=True,normalize_embeddings=True
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
        clusters.setdefault(label, []).append(idx)

    # Convert clusters to list of lists of article indices
    result = list(clusters.values())
    return result

