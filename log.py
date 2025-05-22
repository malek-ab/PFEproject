from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import io

app = Flask(__name__)
CORS(app)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "Aucun fichier reçu"}), 400

    file = request.files['file']
    content = file.read().decode('utf-8')
    df = pd.read_csv(io.StringIO(content), sep=None, engine='python')

    # 1. Comptage des Actions
    if 'Action' in df.columns:
        counts_actions = df['Action'].value_counts().to_dict()
    else:
        counts_actions = {}

    # 2. Moyennes
    avg_bytes      = df['Bytes'].mean() if 'Bytes' in df.columns else None
    avg_sent       = df['Bytes Sent'].mean() if 'Bytes Sent' in df.columns else None
    avg_received   = df['Bytes Received'].mean() if 'Bytes Received' in df.columns else None

    # 3. Top 5 sessions
    top_packets     = df.nlargest(5, 'Packets').to_dict(orient='records')    if 'Packets' in df.columns else []
    top_bytes       = df.nlargest(5, 'Bytes').to_dict(orient='records')      if 'Bytes' in df.columns else []
    long_sessions   = df.nlargest(5, 'Elapsed Time (sec)').to_dict(orient='records') \
                       if 'Elapsed Time (sec)' in df.columns else []

    # 4. Exemple d'anomalies : sessions avec plus de 1M de bytes envoyés
    anomalies = df[df.get('Bytes Sent', 0) > 1_000_000] \
                    [['Bytes Sent', 'Bytes Received']] \
                    .to_dict(orient='records')

    # 5. Construire le JSON de réponse
    result = {
        "counts_actions": counts_actions,
        "avg_bytes": avg_bytes,
        "avg_sent": avg_sent,
        "avg_received": avg_received,
        "top_packets": top_packets,
        "top_bytes": top_bytes,
        "long_sessions": long_sessions,
        "anomalies": anomalies
    }

    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5003, debug=True)
