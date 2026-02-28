def test_history_endpoint(client):
    response = client.get("/reports/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)