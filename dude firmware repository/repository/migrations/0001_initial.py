# Generated by Django 3.2.6 on 2021-08-11 04:51

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Repository',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('manufacturer', models.TextField()),
                ('title', models.TextField()),
                ('version', models.TextField()),
                ('link', models.URLField()),
                ('download_url', models.URLField()),
            ],
        ),
    ]
