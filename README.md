# 🔐 Secure File Transfer Protocol (SFTP) using Java Sockets and RSA
 
This project demonstrates a secure file transfer protocol implemented in Java using **RSA encryption**, **digital signatures**, and **socket programming**. The communication is between two parties — **Alice (Client)** and **Bob (Server)** — enabling encrypted and signed file transfers over a local or remote network.

The system simulates secure file sharing with:
- **Public-key encryption** (RSA)
- **Digital signatures** for integrity & authentication
- **Object-based socket communication**

---

## 🏗️ Project Structure

```
├── SFTProtocol/
│ ├── SFTProtocol.java 
│ ├── AliceClient.java 
│ └── BobServer.java 
├── TopSecret.txt # (Optional) File to be securely sent
├── .gitignore 
└── README.md # You're here!
```

---

## 🛠️ Setup and Run

```
cd Secure-File-Transfer-Protocol-with-RSA/SFTProtocol/src
```

1. **Key Generation**
   - Run once:  
     ```bash
     javac SFTProtocol/SFTProtocol.java
     java SFTProtocol.SFTProtocol
     ```

2. **Start Server (Bob)**
   - Run:
     ```bash
     javac SFTProtocol/BobServer.java
     java SFTProtocol.BobServer
     ```

3. **Start Client (Alice)**
   - Run:
     ```bash
     javac SFTProtocol/AliceClient.java
     java SFTProtocol.AliceClient
     ```

---

## 🤝 Contributors

This project was developed by:
 - [Isuru Deshapriya](https://github.com/i-s-u-r-u)
 - [Sachintha Liyanage](https://github.com/sachinthaliyanage)
 - [Amanada Senevirathna](https://github.com/ACSENEVIRATHNA)
 - [Nirmana Ekanayaka](https://github.com/EkanayakaSAND)
