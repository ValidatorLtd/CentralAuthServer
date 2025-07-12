# CentralAuthServer

A modern, modular, centralized authentication server built with **.NET 9** — supporting real-world authentication and authorization scenarios for web, mobile, and microservices.

---

## ✅ Features (Completed)

### 🔐 Step 1: Project Setup
- .NET 9 solution initialized with clean architecture:
  - `CentralAuthServer.API`, `Core`, `Infrastructure`, `Application`, `Tests`
- Git initialized and pushed to GitHub
- Branches created: `main`, `feature/email-auth`
- `.gitignore` and `.sln` configured

### 🔑 Step 2: Email/Password Login (JWT)
- `ApplicationUser` entity using ASP.NET Identity
- `AuthDbContext` using EF Core and Identity
- `AuthController` with endpoints:
  - `POST /register`
  - `POST /login`
- JWT Token generation and claims
- DTOs for request models
- EF Migrations applied
- Configuration:
  - `appsettings.json` for DB connection and JWT secrets
  - `Program.cs` configured for:
    - EF Core
    - ASP.NET Identity
    - JWT Authentication

---

## 🚧 Roadmap (Upcoming Features)

| Step | Feature                          | Description |
|------|----------------------------------|-------------|
| ✅ 2 | Basic Auth (email/password)      | Completed |
| 3️⃣ | Role-based Authorization         | Add roles (Admin/User), secure routes with `[Authorize(Roles="X")]` |
| 4️⃣ | Forgot/Reset Password            | Token gen + email + reset API |
| 5️⃣ | Email Confirmation               | Require email verification before login |
| 6️⃣ | Session Management               | Track refresh tokens per device/session/IP |
| 7️⃣ | Force Logout                     | Revoke refresh tokens |
| 8️⃣ | MFA                              | Add 2FA with SMS, email, or authenticator apps |
| 9️⃣ | External Logins                  | Google, Facebook, MS OAuth2 logins |
| 🔟  | Link Multiple Providers          | Unify accounts with same email from different providers |
| 11  | Audit Logging                    | Track login history, IP, device info |
| 12  | Admin Dashboard API              | User + role management APIs |
| 13  | Unit Tests                       | xUnit tests for all logic |
| 14  | Frontend                         | Optional Blazor/React UI or use Postman |
| 15  | Deployment                       | Docker + secrets + production deployment (Azure/AWS) |

---

## 🧱 Tech Stack

- **.NET 9**
- **ASP.NET Core Identity**
- **Entity Framework Core**
- **JWT Authentication**
- **SQL Server**
- Clean Architecture: API, Application, Infrastructure, Core

---

## 🏁 Getting Started

1. Clone the repo  
   ```bash
   git clone https://github.com/your-username/CentralAuthServer.git
