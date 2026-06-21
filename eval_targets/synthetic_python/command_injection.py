import subprocess
def handler(user_input):
    subprocess.run(user_input, shell=True)  # CWE-78 TP
