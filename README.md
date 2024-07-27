# debbuger


# <a name="_toc173014000"></a>User Guide:

User requirements.

OS: windows 10 operating system. 32/64-bit Intel architecture 

**Client Side:**

First, the user should generate their own PC ID using the Generate\_PC\_Id.exe file. The file will generate a hex string of fixed size. The user should send their PC ID to the server.

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.004.jpeg)


**Server Side:**

The server will generate the user's license using the License\_Generator.exe file, given the user's PC ID as a command parameter.

Requirements: The server's private key should be in the same directory as License\_Generator.exe. If not, the file will create a new RSA key pair and will use it to generate the license. It's important that the server's public key is available on the client side to verify the license.	

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.005.jpeg)

![](Aspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.006.png)


the License is created in the file License.dat.

Now, we will run the Python code to generate a protected version of the software. There are two Python scripts, one for the 64-bit version and one for the 32-bit version. In this tutorial, we will use the 32-bit version. 

For example, if we want to create a protected version of SoftwareToDemonstrate.exe:

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.007.png)

this software contains a simple snake game. 

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.008.png)

To create a protected version of this game, we should run the protected\_version\_generator32bit.py script in the same directory as the exe file we want to protect. License.dat, get\_exe\_fields.py, Activation\_Program.exe (in the right version), and public.pem (if the server wants to send this to the client as well) should be in the same directory as the Python code. 

Now run the Python script with the name of the file we want to protect. 

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.009.png)

Here, we will run the Python script with the exe file we want to protect and with a limit factor of 5, which is the minimum number of bytes in a block we will encrypt. The default value of this parameter is 10.

After running the Python script, the out folder will be created. 

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.010.png)

The out directory will be sent to the client. 

**Client Side:**

![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.011.png)

This is what the server sends to the client. To activate the SoftwareToDemonstrate.exe\_out.exe file, the client will need to run the Activation\_Program.exe file with all the files in the out directory. ![](user%20guideAspose.Words.f3a901f7-90fb-4b79-adad-4d45856fd7e6.012.png)

It's important to note that this will only work on the computer that provided its PC ID to the server. 


**Summary**

**Client Side:**

Step1: Get the client PC IDs and send them to the server.

**Server Side:**

Step2: Generate the client's license using the PC ID received and run the License\_Generator.exe file.

Step3: Ensure the Activation\_Program.exe file with the correct version is in the directory.

Step4: Generate the protected software by running the protected\_version\_generator32bit.py or protected\_version\_generator64bit.py script with the exe file name you want to protect.

Step5: Send the out directory to the client.

**Client Side:**

Step6: Run the software using Activation\_Program.exe.



