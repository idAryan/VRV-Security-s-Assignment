Objective: Writing a python script that process log files to extract and analyze key information.  

Functionalities  
1.Count Requests per IP Address  
i.Calculate the number of requests  
ii.Sort and display in descending order of request count  

2.Identify the Most Frequently Accessed Endpoint:  
i.Extract the endpoints from log file  
ii.Identify the number of times endpoint accessed  
iii.Provide the endpoint name and its access count  

3.Detect Suspicious activity:  
i.Identify potential brute force login attempt  
	By failed login attempts HTTP status code 401 or “Invalid credentials”  
	Flagged IP address with failed login attempts exceeding 10 attempts(configurable threshold)  
ii.Display Flagged IP addresses with failed login counts  

4.Output Results:  
i.Display the results in organized manner in the terminal  
ii.Save the csv file named log_analysis_results.csv  
	a)Request per IP: IP Address, Request Count  
	b)Most Accessed Endpoint: Endpoint, Access Count  
	c)Suspicious Activity: IP Address,Failed Login Count  

	


