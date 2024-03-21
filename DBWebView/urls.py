from django.urls import path
from . import views
urlpatterns = [
    #views
    path('', views.render_main_page, name='main'),
    path('auth/', views.render_auth_page, name='auth'),
    path('settings/', views.render_settings_page, name='settings'),
    #subpages
    path('table/<str:tablename>', views.render_main_page, name='table'),
    path('view/<str:viewname>', views.render_main_page, name='view'),
    path('trigger/<str:triggername>', views.render_main_page, name='trigger'),
    path('function/<str:functionname>', views.render_main_page, name='function'),
    #export
    path('table/<str:tablename>/<str:export_format>', views.export_table, name='export'),
    path('view/<str:viewname>/<str:export_format>', views.export_table, name='export2'),
    #misc
    path('update-row/', views.update_table_row, name='update_row'),
]
