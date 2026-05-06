"""
Fraud Intelligence - ABFSS Integration
================================================

Components:
    - custom_source_abfss.py: Registers ABFSS with nilus and fetch csv files from input folder of each entity
      and move to Process folder
"""

__version__ = "1.0.0"


from custom_source_abfss import GroupCompanyFraudulentDataSource

__all__ = ["GroupCompanyFraudulentDataSource"]
