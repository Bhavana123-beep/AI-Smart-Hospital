<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Smart Disease Prediction & Hospital Recommendation System</title>

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Google Font -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">

    <!-- Font Awesome -->
    <link rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">

    <!-- Custom CSS -->
    <link rel="stylesheet" href="../static/css/style.css">
    <link rel="stylesheet" href="../static/css/home.css">
</head>

<body>

    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm">
        <div class="container">

            <a class="navbar-brand fw-bold text-primary" href="#">
                <i class="fa-solid fa-hospital"></i>
                Smart Hospital
            </a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">

                <span class="navbar-toggler-icon"></span>

            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <ul class="navbar-nav ms-auto">

                    <li class="nav-item">
                        <a class="nav-link active" href="#">Home</a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link" href="#">About</a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link" href="#">Services</a>
                    </li>

                    <li class="nav-item">
                        <a class="nav-link" href="#">Contact</a>
                    </li>

                    <li class="nav-item ms-3">
                        <a class="btn btn-primary" href="login.html">
                            Login
                        </a>
                    </li>

                    <li class="nav-item ms-2">
                        <a class="btn btn-success" href="register.html">
                            Register
                        </a>
                    </li>

                </ul>

            </div>

        </div>
    </nav>

    <!-- Hero Section -->
    <section class="container py-5">

        <div class="row align-items-center">

            <div class="col-lg-6">

                <h1 class="display-4 fw-bold text-primary">

                    Smart Disease Prediction

                </h1>

                <h3 class="mb-3">

                    Using Machine Learning

                </h3>

                <p class="lead">

                    Predict diseases based on symptoms, get department recommendations,
                    and improve healthcare using Machine Learning.

                </p>

                <a href="register.html" class="btn btn-primary btn-lg">

                    Get Started

                </a>

                <a href="#" class="btn btn-outline-primary btn-lg ms-2">

                    Learn More

                </a>

            </div>

            <div class="col-lg-6 text-center">

                <i class="fa-solid fa-user-doctor"
                    style="font-size:220px;color:#0d6efd;"></i>

            </div>

        </div>

    </section>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

</body>

</html>