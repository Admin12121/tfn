# Generated by Django 4.2.11 on 2024-06-12 09:19

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("account", "0004_alter_user_status"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("received", "received"),
                    ("inprogress", "inprogress"),
                    ("pending", "pending"),
                    ("seentforsign", "seentforsign"),
                    ("signed", "signed"),
                    ("lodgedwithato", "lodgedwithato"),
                    ("dormat", "dormat"),
                ],
                default="received",
                max_length=100,
                null=True,
            ),
        ),
    ]
