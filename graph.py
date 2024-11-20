import pandas as pd
import matplotlib.pyplot as plt

def analyze_and_visualize(file_path):
    """Analyze the data and generate meaningful cybersecurity visualizations."""
    try:
        # Load the dataset
        df = pd.read_csv(file_path)

        # Check if data is improperly formatted (e.g., combined into one column)
        if len(df.columns) == 1:  # Data is combined into a single column
            print("Detected improperly formatted data. Parsing...")
            # Split into multiple columns dynamically
            df_split = df['Threat Type'].str.split('|', expand=True)
            print(f"Detected {len(df_split.columns)} columns after splitting.")

            # Assign column names dynamically based on the actual number of columns
            expected_columns = [
                "Threat Type", "Severity Level", "Affected Systems",
                "Timestamp", "Description", "Suggested Mitigation Steps"
            ]
            # Truncate or add placeholder names if column count differs
            if len(df_split.columns) > len(expected_columns):
                df_split = df_split.iloc[:, :len(expected_columns)]  # Trim extra columns
            elif len(df_split.columns) < len(expected_columns):
                for _ in range(len(expected_columns) - len(df_split.columns)):
                    df_split[f"Extra_Column_{_}"] = None  # Add placeholders for missing columns

            df_split.columns = expected_columns[:len(df_split.columns)]  # Assign names
            df = df_split

        # Strip leading/trailing whitespace from column names and values
        df.columns = df.columns.str.strip()
        df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
        # df = df.apply(lambda x: x.strip() if isinstance(x, str) else x)


        # Inspect the parsed data
        print("Parsed Data Overview:")
        print(df.head())
        print("\nColumn Names:", df.columns)

        # Clean the data
        df = df.dropna()  # Drop rows with missing values

        # Visualization 1: Threat Type Distribution
        plt.figure(figsize=(10, 6))
        threat_counts = df['Threat Type'].value_counts()
        threat_counts.plot(kind='bar', color='skyblue', edgecolor='black')
        plt.title('Threat Type Distribution', fontsize=16)
        plt.xlabel('Threat Type', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig("threat_type_distribution.png")
        plt.show()

        # Visualization 2: Severity Levels
        plt.figure(figsize=(8, 8))
        severity_counts = df['Severity Level'].value_counts()
        severity_counts.plot(kind='pie', autopct='%1.1f%%', startangle=140, colors=['#ff9999','#66b3ff','#99ff99','#ffcc99'])
        plt.title('Severity Levels Distribution', fontsize=16)
        plt.ylabel('')  # Hide the y-label
        plt.tight_layout()
        plt.savefig("severity_levels_distribution.png")
        plt.show()

        # Visualization 3: Affected Systems
        plt.figure(figsize=(10, 6))
        affected_counts = df['Affected Systems'].value_counts()
        affected_counts.plot(kind='bar', color='salmon', edgecolor='black')
        plt.title('Affected Systems Count', fontsize=16)
        plt.xlabel('Affected System', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig("affected_systems_count.png")
        plt.show()

        # Optional Visualization 4: Timestamp Analysis (if timestamps are present)
        if 'Timestamp' in df.columns:
            plt.figure(figsize=(12, 6))
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
            df['Date'] = df['Timestamp'].dt.date  # Extract the date for aggregation
            date_counts = df.groupby('Date').size()
            date_counts.plot(kind='line', marker='o', color='purple')
            plt.title('Threat Occurrences Over Time', fontsize=16)
            plt.xlabel('Date', fontsize=12)
            plt.ylabel('Count', fontsize=12)
            plt.grid(axis='both', linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig("threats_over_time.png")
            plt.show()

        print("Visualizations generated successfully!")

    except Exception as e:
        print(f"Error during analysis or visualization: {e}")

def main():
    # File path to the cybersecurity data
    file_path = "output.csv"

    # Analyze and visualize the data
    analyze_and_visualize(file_path)

if __name__ == "__main__":
    main()