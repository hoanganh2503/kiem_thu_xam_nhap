import joblib
import pandas as pd  # Thêm pandas để tạo DataFrame

class ModelAI:
    def __init__(self, binary_model_path, multi_model_path):
        print("Nap mo hinh")
        # Nạp mô hình từ file .pkl
        self.binary_model = joblib.load(binary_model_path)
        self.multi_model = joblib.load(multi_model_path)
        print("Nap thanh cong")
    def predict_anomaly(self, data_dict):
        try:
            # Chuyển đổi thành DataFrame để giữ nguyên tên cột
            X_input = pd.DataFrame([data_dict])  
            predicted_class = self.binary_model.predict(X_input)
            return predicted_class[0]
        except Exception as e:
            print(f"Loi du doan: {e}")
            return None

    def predict_attack(self, data_dict):
        try:
            # Chuyển đổi thành DataFrame để giữ nguyên tên cột
            X_input = pd.DataFrame([data_dict])  
            predicted_class = self.multi_model.predict(X_input)
            return predicted_class[0]
        except Exception as e:
            print(f"Loi du doan: {e}")
            return None

# Sử dụng mô hình đã lưu
Ai = ModelAI(
    "./Binary_model_randomforest.pkl",
    "./Multi_model_randomforest.pkl"
)

# data = {
#     "sttl": 254,
#     "state_INT": 0,
#     "ct_state_ttl": 0,
#     "proto_tcp": 1,
#     "swin": 255,
#     "dload": 13446.84766,
#     "state_CON": 0,
#     "dwin": 255,
#     "state_FIN": 1
# }

# print(Ai.predict_anomaly(data))
# print(Ai.predict_attack(data))
