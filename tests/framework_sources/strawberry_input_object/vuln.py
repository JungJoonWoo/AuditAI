# 의도적 취약: Strawberry input object field(source) → subprocess(sink). CWE-78.
import strawberry
import subprocess


@strawberry.input
class Cmd:
    line: str


@strawberry.type
class Mutation:
    @strawberry.mutation
    def run(self, cmd: Cmd) -> str:  # source: GraphQL input object field
        return subprocess.check_output(cmd.line, shell=True).decode()  # sink
