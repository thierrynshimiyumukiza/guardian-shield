# scripts/inspect_cic_data.py
import pandas as pd

df = pd.read_csv('../datasets/CIC-IDS2010.csv')
print("Column names:", df.columns.tolist())
print("\nFirst 10 URL values:")
print(df['URL'].head(10).tolist())
print("\nFirst 10 classification values:")
print(df['classification'].head(10).tolist())
print("\nUnique classification values:")
print(df['classification'].unique())