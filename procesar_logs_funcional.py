import pandas as pd
import matplotlib.pyplot as plt
import json
import os
from collections import Counter

# ==========================
# RUTAS
# ==========================

CONN_BENIGNO = r"T:\Universidad\Tesis\datasets\csv_modbusBenigno\conn_completo.csv"
CONN_ATAQUE = r"T:\Universidad\Tesis\datasets\csv_modbusAttck\conn_completo.csv"

MODBUS_BENIGNO = r"T:\Universidad\Tesis\datasets\csv_modbusBenigno\modbus_completo.csv"
MODBUS_ATAQUE = r"T:\Universidad\Tesis\datasets\csv_modbusAttck\modbus_completo.csv"

WEIRD_BENIGNO = r"T:\Universidad\Tesis\datasets\csv_modbusBenigno\weird_completo.csv"
WEIRD_ATAQUE = r"T:\Universidad\Tesis\datasets\csv_modbusAttck\weird_completo.csv"

ANALYZER_ATAQUE = r"T:\Universidad\Tesis\datasets\csv_modbusAttck\analyzer_completo.csv"

HASHES_BENIGNO = r"T:\Universidad\Tesis\datasets\hashes_evidencia2benigno.csv"
HASHES_ATAQUE = r"T:\Universidad\Tesis\datasets\hashes_evidencia2attack.csv"

CHUNK = 500000

os.makedirs("graficos", exist_ok=True)
os.makedirs("resumen", exist_ok=True)

# ==========================
# FUNCIONES
# ==========================
def contar_req_resp(path):

    contador = Counter()

    for chunk in pd.read_csv(
        path,
        sep=";",
        chunksize=CHUNK,
        low_memory=False
    ):

        if "pdu_type" in chunk.columns:

            contador.update(
                chunk["pdu_type"]
                .dropna()
                .astype(str)
            )

    return contador

def top_counter_csv(path, column):

    print(f"\nProcesando: {os.path.basename(path)}")

    c = Counter()

    try:
        for chunk in pd.read_csv(
            path,
            sep=";",
            chunksize=CHUNK,
            low_memory=False
        ):

            if column in chunk.columns:

                datos = (
                    chunk[column]
                    .dropna()
                    .astype(str)
                )

                # eliminar IPv6
                if column in ["id.orig_h", "id.resp_h"]:
                    datos = datos[
                        ~datos.str.contains(":", na=False)
                    ]

                c.update(datos)

    except Exception as e:

        print(f"Error en {path}")
        print(e)

    return pd.DataFrame(
        c.most_common(20),
        columns=[column, "count"]
    )

def timeline_csv(path):

    print(f"\nTimeline: {os.path.basename(path)}")

    series = []

    try:

        for chunk in pd.read_csv(
            path,
            sep=";",
            chunksize=CHUNK,
            low_memory=False
        ):

            if "timestamp" not in chunk.columns:
                continue

            chunk["timestamp"] = pd.to_datetime(
            chunk["timestamp"],
            format="%Y-%m-%d %H:%M:%S",
             errors="coerce"
            )
            

            tmp = (
                chunk
                .dropna(subset=["timestamp"])
                .set_index("timestamp")
                .resample("1h")
                .size()
            )

            series.append(tmp)

    except Exception as e:

        print(f"Error timeline {path}")
        print(e)

    if len(series) == 0:
        return pd.Series(dtype=int)

    return pd.concat(series).groupby(level=0).sum()

def contar_filas(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f) - 1
    
def grafico_comparativo(df_b, df_a, columna, titulo, salida):

    print(f"\nGenerando {salida}")

    if df_b.empty:
        print("Benigno vacío")
        return

    if df_a.empty:
        print("Ataque vacío")
        return

    if columna not in df_b.columns:
        print(f"No existe {columna} en benigno")
        return

    if columna not in df_a.columns:
        print(f"No existe {columna} en ataque")
        return

    categorias = list(
        set(df_b[columna].astype(str))
        |
        set(df_a[columna].astype(str))
    )

    categorias.sort()

    serie_b = (
        df_b.set_index(columna)["count"]
        .reindex(categorias)
        .fillna(0)
    )

    serie_a = (
        df_a.set_index(columna)["count"]
        .reindex(categorias)
        .fillna(0)
    )

    plt.figure(figsize=(14,6))

    x = range(len(categorias))

    plt.bar(
        [i-0.2 for i in x],
        serie_b.values,
        width=0.4,
        label="Benigno"
    )

    plt.bar(
        [i+0.2 for i in x],
        serie_a.values,
        width=0.4,
        label="Ataque"
    )

    plt.xticks(
        x,
        categorias,
        rotation=45,
        ha="right"
    )

    plt.title(titulo)
    plt.ylabel("Cantidad")
    plt.legend()
    plt.yscale("log")
    plt.tight_layout()

    plt.savefig(
        salida,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print("OK")
plt.close()
# ==========================
# TOP IPS ORIGEN
# ==========================

ori_b = top_counter_csv(CONN_BENIGNO, "id.orig_h")
ori_a = top_counter_csv(CONN_ATAQUE, "id.orig_h")

ori_b.to_csv("resumen/origen_benigno.csv", index=False)
ori_a.to_csv("resumen/origen_ataque.csv", index=False)

# ==========================
# TOP IPS DESTINO
# ==========================

dst_b = top_counter_csv(CONN_BENIGNO, "id.resp_h")
dst_a = top_counter_csv(CONN_ATAQUE, "id.resp_h")

dst_b.to_csv("resumen/destino_benigno.csv", index=False)
dst_a.to_csv("resumen/destino_ataque.csv", index=False)

# ==========================
# FUNCIONES MODBUS
# ==========================

func_b = top_counter_csv(MODBUS_BENIGNO, "func")
func_a = top_counter_csv(MODBUS_ATAQUE, "func")

func_b.to_csv("resumen/modbus_benigno.csv", index=False)
func_a.to_csv("resumen/modbus_ataque.csv", index=False)

# ==========================
# REQ VS RESP MODBUS
# ==========================

reqresp_b = contar_req_resp(MODBUS_BENIGNO)
reqresp_a = contar_req_resp(MODBUS_ATAQUE)

categorias = ["REQ", "RESP"]

benigno = [
    reqresp_b.get("REQ", 0),
    reqresp_b.get("RESP", 0)
]

ataque = [
    reqresp_a.get("REQ", 0),
    reqresp_a.get("RESP", 0)
]

x = range(len(categorias))

plt.figure(figsize=(8,5))

plt.bar(
    [i-0.2 for i in x],
    benigno,
    width=0.4,
    label="Benigno"
)

plt.bar(
    [i+0.2 for i in x],
    ataque,
    width=0.4,
    label="Ataque"
)

plt.xticks(x, categorias)

plt.ylabel("Cantidad")
plt.title("Solicitudes y Respuestas Modbus")

plt.legend()
plt.tight_layout()

plt.savefig(
    "graficos/modbus_req_resp.png",
    dpi=300
)

plt.close()

# ==========================
# WEIRD
# ==========================

weird_b = top_counter_csv(WEIRD_BENIGNO, "name")
weird_a = top_counter_csv(WEIRD_ATAQUE, "name")

weird_b.to_csv("resumen/weird_benigno.csv", index=False)
weird_a.to_csv("resumen/weird_ataque.csv", index=False)

# ==========================
# ANALYZER
# ==========================
if os.path.exists(ANALYZER_ATAQUE):

    ana_a = top_counter_csv(
        ANALYZER_ATAQUE,
        "failure_reason"
    )

    ana_a.to_csv(
        "resumen/analyzer.csv",
        index=False
    )

    plt.figure(figsize=(12,6))

    etiquetas = [
        f"Evento {i+1}"
        for i in range(len(ana_a))
    ]

    plt.bar(
        etiquetas,
        ana_a["count"]
    )

    plt.title(
        "Errores Detectados por Analyzer"
    )

    plt.ylabel(
        "Cantidad"
    )

    plt.tight_layout()

    plt.savefig(
        "graficos/analyzer.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

# ==========================
# TIMELINE
# ==========================

timeline_b = timeline_csv(CONN_BENIGNO)
timeline_a = timeline_csv(CONN_ATAQUE)

if len(timeline_b) > 0 and len(timeline_a) > 0:

    plt.figure(figsize=(12,5))

    plt.plot(
        timeline_b.index,
        timeline_b.values,
        label="Benigno"
    )

    plt.plot(
        timeline_a.index,
        timeline_a.values,
        label="Ataque"
    )

    plt.legend()
    plt.title("Eventos a traves del tiempo")
    plt.xlabel("Tiempo")
    plt.ylabel("Cantidad de eventos")
    plt.tight_layout()

    plt.savefig(
        "graficos/timeline.png",
        dpi=300
    )

    plt.close()
# ==========================
print("\nDEBUG DESTINO")
print(dst_b.head())
print(dst_a.head())

print("\nDEBUG MODBUS")
print(func_b.head())
print(func_a.head())

print("\nDEBUG WEIRD")
print(weird_b.head())
print(weird_a.head())

print("\nTAMAÑOS")
print("dst_b:", len(dst_b))
print("dst_a:", len(dst_a))
print("func_b:", len(func_b))
print("func_a:", len(func_a))
print("weird_b:", len(weird_b))
print("weird_a:", len(weird_a))
print("\nDESTINO BENIGNO")
print(dst_b.head())

print("\nDESTINO ATAQUE")
print(dst_a.head())

print("\nMODBUS BENIGNO")
print(func_b.head())

print("\nMODBUS ATAQUE")
print(func_a.head())

print("\nWEIRD BENIGNO")
print(weird_b.head())

print("\nWEIRD ATAQUE")
print(weird_a.head())
print(dst_b.columns)
print(dst_a.columns)

print(func_b.columns)
print(func_a.columns)

print(weird_b.columns)
print(weird_a.columns)

grafico_comparativo(
    dst_b,
    dst_a,
    "id.resp_h",
    "IPs de Destino más Comunes",
    "graficos/ip_destino.png"
)

print("IP DESTINO OK")

grafico_comparativo(
    dst_b,
    dst_a,
    "id.resp_h",
    "IPs de Destino más Comunes",
    "graficos/ip_destino.png"
)

grafico_comparativo(
    func_b,
    func_a,
    "func",
    "Funciones Modbus",
    "graficos/modbus_funciones.png"
)

print("MODBUS OK")

grafico_comparativo(
    weird_b,
    weird_a,
    "name",
    "Eventos Weird",
    "graficos/weird.png"
)

print("WEIRD OK")

grafico_comparativo(
    func_b,
    func_a,
    "func",
    "Funciones Modbus mas Utilizadas",
    "graficos/modbus_funciones.png"
)
print("\nORIGEN ATAQUE")
print(ori_a)
grafico_comparativo(
    ori_b,
    ori_a,
    "id.orig_h",
    "IPs de Origen más Comunes",
    "graficos/ip_origen.png"
)

print("IP ORIGEN OK")

# ==========================
# HASHES
# ==========================

hash_b = pd.read_csv(HASHES_BENIGNO)
hash_a = pd.read_csv(HASHES_ATAQUE)
# ==========================
# GRAFICO HASHES
# ==========================

plt.figure(figsize=(7,7))

plt.pie(
    [len(hash_b), len(hash_a)],
    labels=["Benigno", "Ataque"],
    autopct="%1.1f%%"
)

plt.title(
    "Distribución de Evidencias SHA-256"
)

plt.savefig(
    "graficos/hashes.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()
# ==========================
# ESTADISTICAS
# ==========================

stats = {

    "conexiones_benigno":
        contar_filas(CONN_BENIGNO),

    "conexiones_ataque":
        contar_filas(CONN_ATAQUE),

    "modbus_benigno":
        contar_filas(MODBUS_BENIGNO),

    "modbus_ataque":
        contar_filas(MODBUS_ATAQUE),

    "weird_benigno":
        contar_filas(WEIRD_BENIGNO),

    "weird_ataque":
        contar_filas(WEIRD_ATAQUE),

    "analyzer_ataque":
        contar_filas(ANALYZER_ATAQUE),

    "hashes_benigno":
        len(hash_b),

    "hashes_ataque":
        len(hash_a)

}

with open(
    "estadisticas.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        stats,
        f,
        indent=4,
        ensure_ascii=False
    )

print("\n=================================")
print("PROCESAMIENTO FINALIZADO")
print("=================================")
print("Archivos generados:")
print("resumen/")
print("graficos/")
print("estadisticas.json")
print("=================================")
print("\nGraficos generados:")

for archivo in os.listdir("graficos"):
    print(" -", archivo)

print("\nResumen generado:")

for archivo in os.listdir("resumen"):
    print(" -", archivo)
    print("\nARCHIVOS EN GRAFICOS:")

for f in sorted(os.listdir("graficos")):
    print(f)