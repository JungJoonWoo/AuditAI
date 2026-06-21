import shlex, subprocess
def handler(x):
    subprocess.run(["echo", shlex.quote(x)])  # sanitizer sufficient: expect FP-reduced
