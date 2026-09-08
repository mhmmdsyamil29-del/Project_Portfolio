# -------- 1. IMPORT LIBRARIES & PROJECT SETUP --------
import os
import pandas as pd

# Project folders
DATA_DIR = 'data'
REPORTS_DIR = 'reports'
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Supported data file
DATA_FILE = os.path.join(DATA_DIR, 'call_data.csv')

# Program info
APP_NAME = "CALL & SIGNAL TRACKER"
APP_VERSION = "1.0"
AUTHOR = "h4cker_fawad"
DESCRIPTION = "Analyze your own call logs & mobile network signals."

# Expected columns in the imported CSV/JSON:
# timestamp, call_type, phone_number, duration, cell_id,
# lac, mcc, mnc, radio_type, rsrp (signal_strength)


def show_menu():
    """Print the main menu."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 60)
    print(f" {APP_NAME} v{APP_VERSION} ")
    print("=" * 60)
    print("1. Import Data (CSV / JSON)")
    print("2. View Call Logs")
    print("3. View All Records")
    print("4. Analyze Signal Strength")
    print("5. Export Report (CSV)")
    print("6. Exit")
    print("-" * 60)


# -------- 2. IMPORT DATA (CSV / JSON) --------
def load_data(file_path):
    """Load data from a CSV or JSON file into a DataFrame."""
    ext = os.path.splitext(file_path)[1].lower()

    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return pd.DataFrame()

    try:
        if ext == '.csv':
            df = pd.read_csv(file_path)
        elif ext == '.json':
            df = pd.read_json(file_path)
        else:
            print("[!] Unsupported file format. Please use CSV or JSON.")
            return pd.DataFrame()
    except Exception as e:
        print(f"[!] Error loading file: {e}")
        return pd.DataFrame()

    if df.empty:
        print("[!] No data found in the file.")
        return pd.DataFrame()

    print(f"[+] Data loaded successfully. Total records: {len(df)}")
    return df


def import_data():
    """Prompt the user to choose and load a CSV/JSON file."""
    print("\n[1] Import CSV file")
    print("[2] Import JSON file")
    choice = input("Select option (1-2): ").strip()
    file_path = input("Enter file path: ").strip().strip('"')

    if choice == '1' and not file_path.lower().endswith('.csv'):
        print("[!] Please select a CSV file.")
        return pd.DataFrame()
    if choice == '2' and not file_path.lower().endswith('.json'):
        print("[!] Please select a JSON file.")
        return pd.DataFrame()
    if choice not in ('1', '2'):
        print("[!] Invalid option selected.")
        return pd.DataFrame()

    return load_data(file_path)


# -------- 3. VIEW & SEARCH RECORDS --------
def view_all_records(df):
    """View all records in a formatted table."""
    if df.empty:
        print("[!] No records to display.")
        return
    with pd.option_context('display.max_rows', None, 'display.width', None):
        print(df.sort_values('timestamp', ascending=False).reset_index(drop=True))


def view_call_logs(df):
    """View call logs only (incoming/outgoing/missed)."""
    if df.empty or 'call_type' not in df.columns:
        print("[!] No call logs found.")
        return
    calls = df[df['call_type'].astype(str).str.upper().isin(
        ['INCOMING', 'OUTGOING', 'MISSED'])]
    if calls.empty:
        print("[!] No call logs found.")
        return
    print(calls.sort_values('timestamp', ascending=False).reset_index(drop=True))


def search_by_number(df):
    """Search records by phone number."""
    number = input("\nEnter phone number to search: ").strip()
    res = df[df['phone_number'].astype(str).str.contains(number, na=False)]
    if res.empty:
        print(f"[!] No records found for {number}")
    else:
        print(res.sort_values('timestamp', ascending=False).reset_index(drop=True))


def filter_by_date(df):
    """Filter records by a start/end date range."""
    start = input("Start date (YYYY-MM-DD HH:MM:SS): ").strip()
    end = input("End date (YYYY-MM-DD HH:MM:SS): ").strip()
    try:
        res = df[(df['timestamp'] >= start) & (df['timestamp'] <= end)]
        if res.empty:
            print("[!] No records found in this range.")
        else:
            print(res.sort_values('timestamp', ascending=False).reset_index(drop=True))
    except Exception as e:
        print(f"[!] Invalid date format or error: {e}")


# -------- 4. ANALYZE SIGNAL STRENGTH & NETWORK DATA --------
def analyze_signal_strength(df):
    """Analyze signal strength (RSRP)."""
    if df.empty:
        print("[!] No data available to analyze.")
        return
    df = df.copy()
    df['rsrp'] = pd.to_numeric(df['rsrp'], errors='coerce')
    df = df.dropna(subset=['rsrp'])
    if df.empty:
        print("[!] No valid RSRP values found.")
        return

    max_row = df.loc[df['rsrp'].idxmax()]  # Strongest signal
    min_row = df.loc[df['rsrp'].idxmin()]  # Weakest signal
    avg_rsrp = df['rsrp'].mean()

    print("\n========== SIGNAL STRENGTH ANALYSIS ==========")
    print(f"Total records analyzed : {len(df)}")
    print(f"Average RSRP           : {avg_rsrp:.2f} dBm")
    print(f"Strongest Signal        : {max_row['rsrp']} dBm")
    print(f"   Cell ID              : {max_row['cell_id']}")
    print(f"Weakest Signal          : {min_row['rsrp']} dBm")
    print(f"   Cell ID              : {min_row['cell_id']}")
    return df


def analyze_network_types(df):
    """Show network type (radio_type) distribution."""
    if df.empty:
        print("[!] No data available to analyze.")
        return
    dist = df['radio_type'].value_counts(dropna=False)
    print("\n========== NETWORK TYPE DISTRIBUTION ==========")
    for net_type, count in dist.items():
        print(f"{net_type:<15} : {count}")
    return dist


def top_cells_by_signal(df, top_n=5):
    """Show top N cells by average RSRP."""
    if df.empty:
        print("[!] No data available to analyze.")
        return
    top_cells = (
        df.dropna(subset=['rsrp'])
        .groupby('cell_id')['rsrp']
        .mean()
        .sort_values(ascending=False)
        .head(top_n)
    )
    print(f"\n========== TOP {top_n} CELLS (by Avg RSRP) ==========")
    for cell_id, avg in top_cells.items():
        print(f"Cell ID: {cell_id:<20} Avg RSRP: {avg:.2f} dBm")
    return top_cells


# -------- 5. EXPORT REPORT & MAIN PROGRAM LOOP --------
def export_report(df, filename='report.csv'):
    """Export filtered/all data to a CSV report."""
    if df.empty:
        print("[!] No data to export.")
        return
    try:
        path = os.path.join(REPORTS_DIR, filename)
        df.to_csv(path, index=False)
        print(f"[+] Report exported successfully: {path}")
    except Exception as e:
        print(f"[!] Error exporting report: {e}")


def show_summary(df):
    """Show summary statistics for the loaded data."""
    if df.empty:
        print("[!] No data available.")
        return
    total = len(df)
    rsrp = pd.to_numeric(df['rsrp'], errors='coerce')
    avg_rsrp = rsrp.mean()
    strongest = rsrp.max()
    weakest = rsrp.min()

    print("\n========== DATA SUMMARY ==========")
    print(f"Total Records         : {total}")
    print(f"Average RSRP (dBm)    : {avg_rsrp:.2f}")
    print(f"Strongest Signal (dBm): {strongest} "
          f"(Cell ID: {df.loc[rsrp.idxmax(), 'cell_id']})")
    print(f"Weakest Signal (dBm)  : {weakest} "
          f"(Cell ID: {df.loc[rsrp.idxmin(), 'cell_id']})")
    print("=" * 40, "\n")


def main():
    df = pd.DataFrame()  # global DataFrame to hold loaded data
    while True:
        show_menu()
        choice = input("Select an option (1-6): ").strip()

        if choice == '1':
            df = import_data()
        elif choice == '2':
            view_call_logs(df)
        elif choice == '3':
            view_all_records(df)
        elif choice == '4':
            analyze_signal_strength(df)
            analyze_network_types(df)
            top_cells_by_signal(df)
        elif choice == '5':
            filename = input("Enter report filename (e.g. report.csv): ").strip()
            export_report(df, filename or 'report.csv')
        elif choice == '6':
            print("[+] Exiting... Stay safe!")
            break
        else:
            print("[!] Invalid option. Please choose 1-6.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()