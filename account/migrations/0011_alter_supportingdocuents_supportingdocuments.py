# Generated by Django 4.2.11 on 2024-06-25 07:26

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("account", "0010_alter_passport_drivinglicense_passport_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="supportingdocuents",
            name="supportingdocuments",
            field=models.ImageField(
                blank=True,
                null=True,
                upload_to="user/documents",
                validators=[
                    django.core.validators.FileExtensionValidator(
                        allowed_extensions=[
                            "jpg",
                            "jpeg",
                            "png",
                            "pdf",
                            "docs",
                            "csv",
                            "xlsx",
                        ]
                    )
                ],
            ),
        ),
    ]
