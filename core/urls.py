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
    path("me/keys/", views.MyKeyPairsView.as_view(), name="my-keys"),
    path("users/<str:username>/public-key/", views.UserPublicKeyView.as_view(), name="user-public-key"),
    # Files
    path("files/", views.FileListCreateView.as_view(), name="file-list"),
    path("files/<int:pk>/", views.FileDetailView.as_view(), name="file-detail"),
    path("files/<int:pk>/download/", views.FileDownloadView.as_view(), name="file-download"),
    path("files/<int:pk>/ciphertext/", views.FileCiphertextView.as_view(), name="file-ciphertext"),
    path("files/<int:pk>/benchmark/", views.FileBenchmarkView.as_view(), name="file-benchmark"),
    # Sharing (patient side)
    path("files/<int:pk>/shares/", views.FileShareListCreateView.as_view(), name="file-shares"),
    path("shares/<int:pk>/", views.FileShareRevokeView.as_view(), name="share-revoke"),
    # Sharing (doctor side)
    path("shares/received/", views.ReceivedShareListView.as_view(), name="shares-received"),
    path("shares/received/<int:pk>/open/", views.ReceivedShareOpenView.as_view(), name="share-open"),
    # Analysis
    path("access-requests/", views.AccessRequestListCreateView.as_view(), name="access-requests"),
    path("access-requests/<int:pk>/", views.AccessRequestDetailView.as_view(), name="access-request-detail"),
    path("access-requests/<int:pk>/deny/", views.AccessRequestDenyView.as_view(), name="access-request-deny"),
    path("analysis/downloads/", views.DownloadHistoryView.as_view(), name="download-history"),
    path("analysis/timings/", views.TimingAnalysisView.as_view(), name="timing-analysis"),
]
