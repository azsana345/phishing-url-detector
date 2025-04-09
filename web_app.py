from flask import Flask, render_template_string, request, Response, url_for
from heuristics import check_phishing
from ml_model import predict_url
import csv

app = Flask(__name__)
url_history = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>PhishDetect</title>
  <link rel=\"icon\" href=\"{{ url_for('static', filename='favicon.png') }}\" type=\"image/png\">
  <style>
    body {
      background-color: #ffffff;
      font-family: 'Segoe UI', sans-serif;
      margin: 0;
      padding: 0;
      color: #1e293b;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    header {
      padding: 2rem;
      text-align: center;
    }
    header img {
      width: 80px;
      height: auto;
      margin-bottom: 0.5rem;
    }
    header h1 {
      margin: 0;
      font-size: 2.4rem;
      color: #1e293b;
      letter-spacing: 1px;
    }
    main {
      width: 100%;
      max-width: 850px;
      padding: 2rem;
    }
    form {
      display: flex;
      margin-bottom: 2rem;
      box-shadow: 0 6px 18px rgba(0,0,0,0.08);
      border-radius: 12px;
      overflow: hidden;
    }
    input[type=\"text\"] {
      flex: 1;
      padding: 1rem 1.2rem;
      font-size: 1rem;
      border: none;
      background: #f3f4f6;
      color: #111827;
      outline: none;
    }
    input[type=\"text\"]::placeholder {
      color: #9ca3af;
    }
    button {
      background-color: #29797d;
      color: white;
      padding: 0 2rem;
      border: none;
      font-size: 1rem;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    button:hover {
      background-color: #215d60;
    }
    .card {
      background: #f9fafb;
      border-radius: 14px;
      padding: 1.8rem;
      box-shadow: 0 4px 10px rgba(0,0,0,0.05);
      margin-bottom: 2rem;
      color: #1e293b;
    }
    .badge {
      padding: 6px 14px;
      font-weight: bold;
      border-radius: 9999px;
      font-size: 0.9rem;
    }
    .phishing {
      background-color: #fee2e2;
      color: #b91c1c;
    }
    .legit {
      background-color: #d1fae5;
      color: #065f46;
    }
    ul.reasons {
      margin-top: 1rem;
      padding-left: 1.5rem;
    }
    ul.reasons li {
      line-height: 1.6;
    }
    table {
      width: 100%;
      margin-top: 1rem;
      border-collapse: collapse;
    }
    th, td {
      border: 1px solid #e5e7eb;
      padding: 12px;
      color: #1e293b;
    }
    th {
      background-color: #f3f4f6;
    }
    .export-btn {
      margin-top: 1rem;
      padding: 12px 20px;
      background: #29797d;
      color: white;
      border: none;
      font-size: 16px;
      border-radius: 8px;
      cursor: pointer;
    }
    .export-btn:hover {
      background-color: #215d60;
    }
  </style>
</head>
<body>
  <header>
    <img src=\"{{ url_for('static', filename='logo.png') }}\" alt=\"PhishDetect Logo\" />
    <h1>PhishDetect</h1>
  </header>
  <main>
    <form method=\"POST\">
      <input type=\"text\" name=\"url\" placeholder=\"Enter a URL to check...\" required />
      <button type=\"submit\">Check</button>
    </form>

    {% if result %}
    <div class=\"card\">
      <p><strong>URL:</strong> {{ url }}</p>
      <p><strong>Domain:</strong> {{ result['domain'] }}</p>
      <p><strong>Phishing Score:</strong> {{ result['phishing_score'] }}%</p>
      <p><strong>Heuristic:</strong>
        <span class=\"badge {{ 'phishing' if result['is_phishing'] else 'legit' }}\">
          {{ 'Phishing' if result['is_phishing'] else 'Legitimate' }}
        </span>
      </p>
      <p><strong>ML Prediction:</strong>
        <span class=\"badge {{ 'phishing' if ml_prediction == 1 else 'legit' }}\">
          {{ 'Phishing' if ml_prediction == 1 else 'Legitimate' }} ({{ (ml_confidence * 100) | round(2) }}% confidence)
        </span>
      </p>
      <p><strong>Why was this flagged?</strong></p>
      <ul class=\"reasons\">
        {% for reason in result['reasons'] %}<li>{{ reason }}</li>{% endfor %}
      </ul>
    </div>

    <div class=\"card\" style=\"display: flex; align-items: flex-start; gap: 20px;\">
      <div style=\"flex-shrink: 0;\">
        <canvas id=\"scoreChart\" width=\"140\" height=\"140\"></canvas>
      </div>
      <div style=\"flex: 1;\">
        <p style=\"margin: 0; font-weight: bold;\">Graph Overview</p>
        <p style=\"font-size: 0.95rem; line-height: 1.6;\">
          This chart visually represents the phishing likelihood based on combined heuristic and ML evaluation.
        </p>
      </div>
    </div>

    <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
    <script>
      const ctx = document.getElementById('scoreChart').getContext('2d');
      new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Phishing Likelihood', 'Legitimacy Confidence'],
          datasets: [{
            data: [{{ result['phishing_score'] }}, {{ 100 - result['phishing_score'] }}],
            backgroundColor: ['#ef4444', '#10b981'],
          }]
        },
        options: {
          plugins: {
            legend: { position: 'bottom' }
          }
        }
      });
    </script>
    {% endif %}

    {% if history %}
    <div class=\"card\">
      <h3>Recently Checked URLs</h3>
      <table>
        <thead>
          <tr><th>URL</th><th>Score (%)</th><th>Heuristic</th><th>ML Prediction</th></tr>
        </thead>
        <tbody>
          {% for entry in history %}
          <tr>
            <td>{{ entry.url }}</td>
            <td>{{ entry.score }}</td>
            <td>{{ entry.heuristic }}</td>
            <td>{{ entry.ml }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      <form method=\"POST\" action=\"/export\">
        <button class=\"export-btn\" type=\"submit\">Export as CSV</button>
      </form>
    </div>
    {% endif %}
  </main>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    ml_prediction = None
    ml_confidence = 0
    url = ""
    if request.method == "POST":
        url = request.form["url"]
        result = check_phishing(url)
        ml_prediction, ml_confidence = predict_url(url)

        url_history.append({
            "url": url,
            "score": result["phishing_score"],
            "heuristic": "Phishing" if result["is_phishing"] else "Legitimate",
            "ml": f"{'Phishing' if ml_prediction == 1 else 'Legitimate'} ({round(ml_confidence * 100, 2)}%)"
        })

    return render_template_string(
        HTML_TEMPLATE,
        result=result,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        url=url,
        history=url_history,
    )

@app.route("/export", methods=["POST"])
def export():
    def generate():
        data = "URL,Phishing Score,Heuristic,ML Prediction\n"
        for entry in url_history:
            data += f"{entry['url']},{entry['score']},{entry['heuristic']},{entry['ml']}\n"
        return data

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=phishing_results.csv"}
    )

if __name__ == "__main__":
    app.run(debug=True)