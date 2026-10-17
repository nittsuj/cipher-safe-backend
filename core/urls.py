from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

urlpatterns = [
    # Authentication
    path("auth/register/", views.RegisterView.as_view(), name="register"),
    path("auth/login/", views.LoginView.as_view(), name="login"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    # Account
    path("me/", views.MeView.as_view(), name="me"),
    path("me/personal-data/", views.PersonalDataView.as_view(), name="personal-data"),
    # Files
    path("files/", views.FileListCreateView.as_view(), name="file-list"),
    path("files/<int:pk>/", views.FileDetailView.as_view(), name="file-detail"),
    path("files/<int:pk>/download/", views.FileDownloadView.as_view(), name="file-download"),
    path("files/<int:pk>/benchmark/", views.FileBenchmarkView.as_view(), name="file-benchmark"),
    # Analysis
    path("analysis/downloads/", views.DownloadHistoryView.as_view(), name="download-history"),
    path("analysis/timings/", views.TimingAnalysisView.as_view(), name="timing-analysis"),
]
