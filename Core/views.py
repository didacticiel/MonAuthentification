from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *

@login_required
def Home(request):
    # Affiche la page d'accueil uniquement pour les utilisateurs connectés
    return render(request, 'core/index.html')

    """
    username = request.POST["username"]
        email = request.POST["email"]
        fname = request.POST["firstname"]
        lname = request.POST["lastname"]
        profile = request.FILES.get("profile")
        print(f"--------------------------Profile: {profile}----------------------------")
        cover = request.FILES.get('cover')
        print(f"--------------------------Cover: {cover}----------------------------")

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
    """
def RegisterView(request):
    # Vérifie si la méthode de la requête est POST
    if request.method == "POST":
        # Récupère les données du formulaire d'inscription
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        user_data_has_error = False

        # Vérifie si le nom d'utilisateur existe déjà
        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "Le nom d'utilisateur existe déjà.")

        # Vérifie si l'adresse e-mail existe déjà
        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "L'adresse e-mail existe déjà.")

        # Vérifie la longueur du mot de passe
        if len(password) < 5:
            user_data_has_error = True
            messages.error(request, "Le mot de passe doit contenir au moins 5 caractères.")

        # Si des erreurs sont présentes, redirige vers la page d'inscription
        if user_data_has_error:
            return redirect('register')
        else:
            # Crée un nouvel utilisateur
            new_user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password
            )
            messages.success(request, "Compte créé. Vous pouvez maintenant vous connecter.")
            return redirect('login')  # Redirige vers la page de connexion

    # Affiche le template pour la page d'inscription si la méthode n'est pas POST
    return render(request, 'core/register.html')

def LoginView(request):
    # Vérifie si la méthode de la requête est POST
    if request.method == "POST":
        # Récupère le nom d'utilisateur et le mot de passe du formulaire
        username = request.POST.get("username")
        password = request.POST.get("password")
        
        

        # Authentifie l'utilisateur avec les informations fournies
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Si l'authentification réussit, connecte l'utilisateur
            login(request, user)
            return redirect('home')  # Redirige vers la page d'accueil
        else:
            # Si l'authentification échoue, affiche un message d'erreur
            messages.error(request, "Identifiants de connexion invalides")
            return redirect('login')  # Redirige vers la page de connexion

    # Affiche le template pour la page de connexion
    return render(request, 'core/login.html')

def LogoutView(request):
    # Déconnecte l'utilisateur
    logout(request)
    return redirect('login')  # Redirige vers la page de connexion après déconnexion

def ForgotPassword(request):
    # Vérifie si la méthode de la requête est POST
    if request.method == "POST":
        # Récupère l'adresse e-mail du formulaire
        email = request.POST.get('email')

        try:
            # Tente de récupérer l'utilisateur correspondant à l'adresse e-mail fournie
            user = User.objects.get(email=email)

            # Crée un nouvel enregistrement de réinitialisation de mot de passe
            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            # Génère l'URL pour réinitialiser le mot de passe
            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            # Construit l'URL complète pour la réinitialisation du mot de passe
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            # Corps du message e-mail avec le lien de réinitialisation
            email_body = f'Réinitialisez votre mot de passe en utilisant le lien ci-dessous :\n\n\n{full_password_reset_url}'
        
            # Crée un message e-mail
            email_message = EmailMessage(
                'Réinitialisez votre mot de passe',  # Sujet de l'e-mail
                email_body,
                settings.EMAIL_HOST_USER,  # Expéditeur de l'e-mail
                [email]  # Destinataire de l'e-mail 
            )

            email_message.fail_silently = True  # Ignore les erreurs d'envoi d'e-mail
            email_message.send()  # Envoie l'e-mail

            # Redirige vers la page indiquant que le lien a été envoyé
            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            # Si aucun utilisateur n'est trouvé avec cette adresse e-mail, affiche un message d'erreur
            messages.error(request, f"Aucun utilisateur trouvé avec l'adresse e-mail '{email}'")
            return redirect('forgot-password')

    # Affiche le template pour la page de mot de passe oublié
    return render(request, 'core/forgot_password.html')

def PasswordResetSent(request, reset_id):
    # Vérifie si le code de réinitialisation existe dans la base de données
    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')  # Affiche la page indiquant que le lien a été envoyé
    else:
        # Redirige vers la page "mot de passe oublié" si le code n'existe pas et affiche un message d'erreur
        messages.error(request, 'Identifiant de réinitialisation invalide')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):
    try:
        # Récupérer l'objet PasswordReset correspondant à l'identifiant de réinitialisation
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            # Récupérer les mots de passe du formulaire
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            # Vérifier si les mots de passe correspondent
            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Les mots de passe ne correspondent pas.')

            # Vérifier la longueur du mot de passe
            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Le mot de passe doit contenir au moins 5 caractères.')

            # Vérifier si le lien de réinitialisation a expiré
            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)
            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Le lien de réinitialisation a expiré.')
                password_reset_id.delete()  # Supprimer l'objet PasswordReset expiré

            # Si tout est valide, mettre à jour le mot de passe
            if not passwords_have_error:
                user = password_reset_id.user  # Récupérer l'utilisateur associé
                user.set_password(password)  # Mettre à jour le mot de passe
                user.save()  # Enregistrer l'utilisateur

                password_reset_id.delete()  # Supprimer l'objet PasswordReset après utilisation

                messages.success(request, 'Mot de passe réinitialisé. Vous pouvez maintenant vous connecter.')
                return redirect('login')  # Rediriger vers la page de connexion

            else:
                # Rediriger vers la page de réinitialisation avec les erreurs affichées
                return redirect('reset-password', reset_id=reset_id)

    except PasswordReset.DoesNotExist:
        # Si l'identifiant de réinitialisation est invalide, rediriger vers la page de mot de passe oublié
        messages.error(request, 'Identifiant de réinitialisation invalide.')
        return redirect('forgot-password')

    return render(request, 'core/reset_password.html')  # Afficher le template pour la réinitialisation du mot de passe