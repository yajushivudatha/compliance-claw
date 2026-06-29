import logging
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

logger = logging.getLogger(__name__)

_vectorstore = None

def get_vectorstore():
    global _vectorstore
    if _vectorstore is None:
        logger.info("Initialising ChromaDB vectorstore...")
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        _vectorstore = Chroma(
            persist_directory="./chroma_db",
            embedding_function=embeddings
        )
        logger.info("ChromaDB vectorstore ready")
    return _vectorstore

def search_cis(query, k=4):                              # ← was k=3
    vectorstore = get_vectorstore()
    results = vectorstore.similarity_search(query, k=k)
    logger.info(f"RAG query: '{query}' → {len(results)} results")
    for i, doc in enumerate(results):
        source = doc.metadata.get('source', 'unknown')
        page   = doc.metadata.get('page', '?')
        logger.debug(f"Result {i+1} [{source.upper()} p{page}]: {doc.page_content[:80]}...")
    return results

def search_by_standard(query, standard, k=4):            # ← was k=3
    vectorstore = get_vectorstore()
    return vectorstore.similarity_search(query, k=k, filter={"source": standard})

def search_mitre(query, k=4):
    """Search only the MITRE ATT&CK chunks."""
    vectorstore = get_vectorstore()
    results = vectorstore.similarity_search(
        query, k=k, filter={"source": "enterprise-attack"}
    )
    logger.info(f"MITRE RAG query: '{query}' → {len(results)} results")
    return results