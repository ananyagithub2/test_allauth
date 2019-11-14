"""CS_AppsStore URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
try:
    from django.urls import include, url
except ImportError:
    from django.conf.urls import include, url
    
from oidc_provider import urls
from django.contrib import admin
from django.views.static import serve
from django.conf import settings
from django.contrib.auth import views as auth_views

from apps_core_services import views


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^signout_view$', views.signout_view),
    url(r'^', include('oidc_provider.urls', namespace='oidc_provider')),
    url(r'^accounts/login/$', auth_views.login, {'template_name': 'login.html'}, name='login'),
    url(r'^apps/$', views.show_apps, name='apps-view'),
    url(r'^login_apps/$', views.login_show_apps, name='login-apps-view'),
    #url(r'^$', views.home_page_view, name='home-page-view'),
]

urlpatterns += [
    url('^phenotype/', include('phenotype.urls')),
    url('^tycho_jupyter/', include('tycho_jupyter.urls')),
    url('^tycho_nextflow/', include('tycho_nextflow.urls')),
    url('^cloudtop_imagej/', include('cloudtop_imagej.urls')),
]


urlpatterns += [
        url(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]