import pickle, yaml
import marshal, dill, jsonpickle
import msgpack, ormsgpack
def a(b): return pickle.loads(b)            # CWE-502 TP
def c(s): return yaml.load(s, yaml.Loader)  # CWE-502 TP
def d(s): return yaml.safe_load(s)          # safe: TN
def e(f): return pickle.load(f)             # CWE-502 TP (LangGraph chain)
def g(b): return ormsgpack.unpackb(b)       # CWE-502 TP (LangGraph chain)
def h(b): return msgpack.unpackb(b)         # CWE-502 TP
def i(b): return msgpack.loads(b)           # CWE-502 TP
def j(b): return marshal.loads(b)           # CWE-502 TP
def k(f): return marshal.load(f)            # CWE-502 TP
def l(b): return dill.loads(b)              # CWE-502 TP
def m(f): return dill.load(f)               # CWE-502 TP
def n(s): return jsonpickle.decode(s)       # CWE-502 TP
