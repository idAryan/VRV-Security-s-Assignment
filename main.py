from display_report import display_report
from csv_writer import save_to_csv
def main():
    log_file='sample.log'
    log_analyze=display_report(log_file)
    save_to_csv(log_analyze,"log_analysis_results.csv")
    print("saved")

if __name__=="__main__":
    main()


            

