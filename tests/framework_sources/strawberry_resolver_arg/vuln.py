# 의도적 취약: Strawberry resolver argument(source) → cursor.execute(sink). CWE-89.
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def user(self, name: str) -> str:  # source: GraphQL resolver arg
        cursor = get_cursor()
        cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # sink: SQLi
        return cursor.fetchone()
