"""Django OpenID WoT Example View."""


import re

from django.urls import reverse, reverse_lazy
from django.views.generic import TemplateView
from django.contrib.auth.models import User, Group
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import redirect

from openid_wargaming.authentication import Authentication
from openid_wargaming.verification import Verification
from openid_wargaming.exceptions import OpenIDVerificationFailed


class FirstStep(TemplateView):
    template_name = 'first.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        components = {
            'scheme': self.request.scheme,
            'host': self.request.get_host(),
            'path': reverse('callback')
        }
        return_to = '{scheme}://{host}{path}'.format(**components)
        auth = Authentication(return_to=return_to)
        url = auth.authenticate('https://eu.wargaming.net/id/openid/')

        context['url'] = url
        return context


class SecondStep(TemplateView):
    template_name = 'second.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        regex = r'https://eu.wargaming.net/id/([0-9]+)-(\w+)/'
        current = self.request.build_absolute_uri()
        verify = Verification(current)

        try:
            identities = verify.verify()
            match = re.search(regex, identities['identity'])
            context['account_id'] = match.group(1)
            context['nickname'] = match.group(2)
            context['authenticated'] = True
            self.create_user(context['nickname'])

        except OpenIDVerificationFailed:
            context['authenticated'] = False
            logout(self.request)

        return context

    def create_user(self, nickname):
        try:
            user = User.objects.get(username__exact=nickname)

        except ObjectDoesNotExist:
            password = User.objects.make_random_password(length=255)
            user = User.objects.create_user(nickname, '', password)
            user.first_name = nickname
            user.save()

        login(self.request, user)
        return user


def logout_user(request):
    logout(request)
    return redirect(reverse('first'))
