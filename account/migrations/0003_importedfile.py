# Generated by Django 4.2.11 on 2024-06-10 06:35

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("account", "0002_user_remark"),
    ]

    operations = [
        migrations.CreateModel(
            name="ImportedFile",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("file_name", models.CharField(max_length=255)),
                ("file_hash", models.CharField(max_length=255, unique=True)),
                ("uploaded_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
