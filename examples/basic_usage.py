from apiris import ApirisClient


if __name__ == "__main__":
    client = ApirisClient(config_path="config.yaml")
    response = client.get("https://api.example.com")

    print(response.data)
    print(response.cad_summary)
    print(response.decision)
    print(response.confidence)

