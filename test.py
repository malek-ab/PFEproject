import pandas as pd
import joblib
from flask import Flask, request, Response
import pyodbc

app = Flask(__name__)

# Chargement du modèle et du scaler
model = joblib.load('model.joblib')
scaler = joblib.load('scaler.joblib')

# Connexion et insertion dans la base SQL Server
def insert_into_db(source_ip, dest_ip, source_port, dest_port, bytes_val, packets_val, generated_rule):
    try:
        conn = pyodbc.connect(
            'DRIVER={ODBC Driver 17 for SQL Server};'
            'SERVER=firewall.mssql.somee.com;'
            'DATABASE=firewall;'
            'UID=Malek;'
            'PWD=malekprojetpfe'
        )
        cursor = conn.cursor()
        query = """
            INSERT INTO dbo.FirewallRules
            (sourceIP, destinationIP, sourcePort, destinationPort, bytes, packets, generatedRule)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        cursor.execute(query, (source_ip, dest_ip, source_port, dest_port, bytes_val, packets_val, generated_rule))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print("Erreur d'insertion dans la base :", e)

# Prédiction avec le modèle ML
def predict_action(source_port, dest_port, bytes_val, packets_val):
    if bytes_val > 1_000_000 or packets_val > 1_000_000:
        return 'deny'
    if bytes_val == 0 and packets_val == 0:
        return 'drop'
    df = pd.DataFrame([[source_port, dest_port, bytes_val, packets_val]],
                      columns=['Source Port', 'Destination Port', 'Bytes', 'Packets'])
    df_scaled = scaler.transform(df)
    return model.predict(df_scaled)[0]

# Génération de la règle nftables
def build_nft_rule(dest_port, action):
    act = 'drop' if action.lower() == 'deny' else action.lower()
    return f"nft add rule ip filter input tcp dport {dest_port} {act}"

# Endpoint principal
@app.route("/generate", methods=["POST"])
def generate_from_json():
    try:
        data = request.get_json()

        # Lecture des champs depuis le JSON
        source_ip   = data.get("sourceIP", "0.0.0.0")
        dest_ip     = data.get("destinationIP", "0.0.0.0")
        source_port = int(data["sourcePort"])
        dest_port   = int(data["destinationPort"])
        bytes_val   = int(data["bytes"])
        packets_val = int(data["packets"])

        # Prédiction et règle
        action = predict_action(source_port, dest_port, bytes_val, packets_val)
        nft_rule = build_nft_rule(dest_port, action)

        # Insertion dans la base de données
        insert_into_db(source_ip, dest_ip, source_port, dest_port, bytes_val, packets_val, nft_rule)

        return Response(nft_rule, status=200, mimetype="text/plain")

    except KeyError as e:
        return Response(f"Champ manquant : {e}", status=400, mimetype="text/plain")
    except ValueError as e:
        return Response(f"Erreur de format : {e}", status=400, mimetype="text/plain")
    except Exception as e:
        return Response(f"Erreur serveur : {e}", status=500, mimetype="text/plain")



if __name__ == "__main__":
    app.run(debug=True, port=5003)
