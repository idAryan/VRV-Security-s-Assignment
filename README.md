#VRV Security’s # Assignment

#Objective: Writing a python script that process log files to extract and analyze key information.  

#Functionalities  
##1.Count Requests per IP Address  
###i.Calculate the number of requests  
###ii.Sort and display in descending order of request count  
![Screenshot from 2024-12-04 00-08-48](https://github.com/user-attachments/assets/10d11b57-32bb-4ea9-8461-7e3b199dc7e6)


##2.Identify the Most Frequently Accessed Endpoint:  
###i.Extract the endpoints from log file  
###ii.Identify the number of times endpoint accessed  
###iii.Provide the endpoint name and its access count  
![Screenshot from 2024-12-04 00-10-15](https://github.com/user-attachments/assets/f157f1b7-8b52-45eb-8dac-5206c85de7d8)


##3.Detect Suspicious activity:  
###i.Identify potential brute force login attempt  
	By failed login attempts HTTP status code 401 or “Invalid credentials”  
	Flagged IP address with failed login attempts exceeding 10 attempts(configurable threshold)  
###ii.Display Flagged IP addresses with failed login counts  
![Screenshot from 2024-12-04 00-10-37](https://github.com/user-attachments/assets/c64c1e2b-5b7f-4812-8cd6-7c8de98abe00)


##4.Output Results:  
###i.Display the results in organized manner in the terminal  
###ii.Save the csv file named log_analysis_results.csv  
	a)Request per IP: IP Address, Request Count  
	b)Most Accessed Endpoint: Endpoint, Access Count  
	c)Suspicious Activity: IP Address,Failed Login Count  
 ![Screenshot from 2024-12-04 00-12-32](https://github.com/user-attachments/assets/a984e4db-3638-4ebb-8197-1659b9f4a753)
 ![Screenshot from 2024-12-04 00-13-03](https://github.com/user-attachments/assets/0adfecc5-2cc4-4677-99f6-7a131a846358)



	


