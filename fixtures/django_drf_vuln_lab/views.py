from django.db.models.expressions import RawSQL
from django.utils.safestring import mark_safe


def search(request):
    query = request.GET.get("q")
    return RawSQL("SELECT * FROM products WHERE name = '" + query, [])


def preview(request):
    content = request.data["content"]
    return mark_safe(content)
