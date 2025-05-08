import psutil

counters = psutil.net_io_counters()

def cucc():
    counters = psutil.net_io_counters()
    print(counters)
    
cucc()
input()