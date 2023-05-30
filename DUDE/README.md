# DUDE
DUDE is a framework for firmware binary decryption, unpacking of various filesystem formats, deobfuscation of obfuscated magic signatures, and endian conversion of big endian cramfs. Moreover, it also provides support for a custom filesystem format which is not supported by the existing toolkits.

Guidelines for running the toolkit:
1. Install Ubuntu 20.04
2. Go to dude directory
3. Setup the enviroment by running dependencies.sh using command sudo ./dependencies.sh 
4. Run command 'celery -A feast_app worker -l info' in terminal
5. Run command 'python3 manage.py runserver' in separate terminal
6. Click on 'Getting Started' button
7. Browse and select firmware
8. Click on 'Firmware Upload' button
9. Unpack the firmware using 'Firmware Unpacking' button
10. Perform static analysis using 'Static Analysis' button
11. Perform code analysis using 'Code Analysis' button
12. Generate detail report using 'Generate Report' button
13. Download the detailed report using "Download Report' button


