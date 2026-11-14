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
    path("me/keys/certificate/", views.MyCertificateView.as_view(), name="my-certificate"),
    path("users/<str:username>/certificate/", views.UserCertificateView.as_view(), name="user-certificate"),
    path("users/<str:username>/public-key/", views.UserPublicKeyView.as_view(), name="user-public-key"),
    # Files
    path("files/", views.FileListCreateView.as_view(), name="file-list"),
    path("files/<int:pk>/", views.FileDetailView.as_view(), name="file-detail"),
    path("files/<int:pk>/sign/", views.FileSignView.as_view(), name="file-sign"),
    path("files/<int:pk>/download/", views.FileDownloadView.as_view(), name="file-download"),
    path("files/<int:pk>/ciphertext/", views.FileCiphertextView.as_view(), name="file-ciphertext"),
    path("files/<int:pk>/benchmark/", views.FileBenchmarkView.as_view(), name="file-benchmark"),
    # Sharing (patient side)
    # Sharing (doctor side)
    # Analysis
    path("access-requests/", views.AccessRequestListCreateView.as_view(), name="access-requests"),
    path("access-requests/<int:pk>/", views.AccessRequestDetailView.as_view(), name="access-request-detail"),
    path("access-requests/<int:pk>/deny/", views.AccessRequestDenyView.as_view(), name="access-request-deny"),
    path(
        "access-requests/<int:pk>/approve/",
        views.AccessRequestApproveView.as_view(),
        name="access-request-approve",
    ),
    path(
        "access-requests/<int:pk>/items/<int:item_id>/envelope/",
        views.GrantedItemEnvelopeView.as_view(),
        name="granted-item-envelope",
    ),
    path(
        "access-requests/<int:pk>/items/<int:item_id>/redeem/",
        views.GrantedItemRedeemView.as_view(),
        name="granted-item-redeem",
    ),
    path("access-requests/<int:pk>/items/<int:item_id>/", views.GrantedItemOpenView.as_view(), name="granted-item"),
    path("analysis/downloads/", views.DownloadHistoryView.as_view(), name="download-history"),
    path("analysis/timings/", views.TimingAnalysisView.as_view(), name="timing-analysis"),
]
