import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from log_analyzer import (
    count_requests_per_ip,
    most_frequent_endpoint,
    detect_suspicious_activity,
    save_results_to_csv,
)

def analyze_log():
    # Get the log file path from the user
    log_file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log"), ("All Files", "*.*")])
    if not log_file_path:
        messagebox.showwarning("No File Selected", "Please select a log file to analyze.")
        return

    try:
        # Perform log analysis
        log_data, ip_data = count_requests_per_ip(log_file_path)
        if log_data and ip_data:
            endpoint_data = most_frequent_endpoint(log_data)
            suspicious_data = detect_suspicious_activity(log_data, threshold=10)
            save_results_to_csv(ip_data, endpoint_data, suspicious_data)

            # Display results in the GUI
            display_results(ip_data, endpoint_data, suspicious_data)
            messagebox.showinfo("Analysis Complete", "Log analysis complete. Results saved to 'log_analysis_results.csv'.")
        else:
            messagebox.showerror("Error", "Failed to analyze the log file.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def display_results(ip_data, endpoint_data, suspicious_data):
    # Clear previous results
    for widget in results_frame.winfo_children():
        widget.destroy()

    # Display Requests per IP
    tk.Label(results_frame, text="Requests per IP", font=("Arial", 14, "bold")).pack(anchor="w")
    ip_tree = ttk.Treeview(results_frame, columns=("IP Address", "Request Count"), show="headings")
    ip_tree.heading("IP Address", text="IP Address")
    ip_tree.heading("Request Count", text="Request Count")
    for ip, count in ip_data:
        ip_tree.insert("", "end", values=(ip, count))
    ip_tree.pack(fill="x", pady=5)

    # Display Most Accessed Endpoint
    tk.Label(results_frame, text="Most Accessed Endpoint", font=("Arial", 14, "bold")).pack(anchor="w")
    tk.Label(results_frame, text=f"{endpoint_data[0]} (Accessed {endpoint_data[1]} times)").pack(anchor="w", pady=5)

    # Display Suspicious Activity
    tk.Label(results_frame, text="Suspicious Activity", font=("Arial", 14, "bold")).pack(anchor="w")
    suspicious_tree = ttk.Treeview(results_frame, columns=("IP Address", "Failed Login Count"), show="headings")
    suspicious_tree.heading("IP Address", text="IP Address")
    suspicious_tree.heading("Failed Login Count", text="Failed Login Count")
    for ip, count in suspicious_data:
        suspicious_tree.insert("", "end", values=(ip, count))
    suspicious_tree.pack(fill="x", pady=5)

# Create the main Tkinter window
root = tk.Tk()
root.title("Log Analyzer")
root.geometry("800x600")

# Heading
tk.Label(root, text="Log Analyzer Tool", font=("Arial", 18, "bold")).pack(pady=10)

# Analyze Button
analyze_button = tk.Button(root, text="Select Log File and Analyze", command=analyze_log, font=("Arial", 12))
analyze_button.pack(pady=10)

# Results Frame
results_frame = tk.Frame(root)
results_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Run the Tkinter event loop
root.mainloop()
