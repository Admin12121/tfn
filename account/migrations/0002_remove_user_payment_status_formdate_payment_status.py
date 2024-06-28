# Generated by Django 4.2.11 on 2024-06-27 05:45

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("account", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="user",
            name="payment_status",
        ),
        migrations.AddField(
            model_name="formdate",
            name="payment_status",
            field=models.CharField(
                blank=True,
                choices=[("paid", "paid"), ("unpaid", "unpaid")],
                default="unpaid",
                max_length=100,
                null=True,
            ),
        ),
    ]