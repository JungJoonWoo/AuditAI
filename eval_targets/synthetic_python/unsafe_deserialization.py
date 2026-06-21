import pickle, yaml
def a(b): return pickle.loads(b)            # CWE-502 TP
def c(s): return yaml.load(s, yaml.Loader)  # CWE-502 TP
def d(s): return yaml.safe_load(s)          # safe: TN
