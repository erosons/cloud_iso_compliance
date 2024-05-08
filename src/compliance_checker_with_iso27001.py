from dataclasses import dataclass, field
from sklearn.preprocessing import LabelEncoder
from typing import Dict, Optional
from pandas import DataFrame
import pandas as pd
from cloud_resource_metadata_extractor import ComplianceManager
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import logging
from sklearn.metrics import classification_report


logger=logging.getLogger()

# Function to load CSV data
def load_training_data() -> pd.DataFrame:
    return pd.read_csv('/Users/s.eromonsei/Documents/MSC/COMP5300/compliance.csv',index_col=False)

@dataclass
class ComplianceAI:
    compliance_container: Dict = field(default_factory=dict)
    training_data: Optional[DataFrame] = field(default_factory=load_training_data)

    @property
    def model_generator(self) -> Dict:
        return self.compliance_container

    @model_generator.setter
    def model_generator(self, value: Dict) -> None:
        if not value:
            raise ValueError("Compliance container cannot be empty")
        else:
            self.compliance_container = value

    def compliance_report_generator(self, reportname: str) -> None:
        # Load training data
        #================================================================
         # Model Training based on ISO27001 data 
        #================================================================
        training_data_df = self.training_data
        training_data_df.columns = range(training_data_df.shape[1])

        # Split data into training and testing sets
        train, test = train_test_split(training_data_df, test_size=0.3)
        x_train = train.iloc[:, 2:-1]
        y_train = train.iloc[:, -1]

        x_test = test.iloc[:, 2:-1]
        y_test = test.iloc[:, -1]

        # Define all possible label values (should include all classes)
        all_labels = [0, 50, 100]

        # Map numeric labels to class names using LabelEncoder
        class_names = {0: "Non-Compliant", 50: "Partially Compliant", 100: "Compliant"}
        encoder = LabelEncoder()
        encoder.fit(all_labels)

        # Encode training and testing labels
        y_train_encoded = encoder.transform(y_train)
        y_test_encoded = encoder.transform(y_test)

        # Train the Decision Tree classifier with encoded labels
        clf = DecisionTreeClassifier()
        clf.fit(x_train, y_train_encoded)

        # Predict on the test data
        y_pred = clf.predict(x_test)

        # Decode predictions back to original numeric labels
        y_pred_numeric = encoder.inverse_transform(y_pred)

        # Translate numeric predictions to target names using the custom mapping
        y_pred_names = [class_names[label] for label in y_pred_numeric]
        logger.info(f"Predicted names: {y_pred_names}")
        print(f"Predicted names: {y_pred_names}")


        # Map the actual numeric labels to target names
        y_actual_names = [class_names[label] for label in y_test]

        # Provide the expected target names for the classification report
        target_names = list(class_names.values())

        # Evaluate using the classification report
        report = classification_report(y_actual_names, y_pred_names, target_names=target_names)

        # Calculate accuracy based on numeric labels
        accuracy = accuracy_score(y_test_encoded, y_pred)
        print(f"Accuracy: {accuracy * 100}%")

        # Save the report to a file
        with open(f'training_prediction_{reportname}.csv', 'w') as f:
            f.write(report)

        #================================================================
         # Predict on the new data extracted from AWS
        #================================================================

        new_df = pd.DataFrame(self.compliance_container,index=[0])
        print(new_df)

    
        y_pred_new = clf.predict(new_df)
        print(y_pred_new)
        #new_report = classification_report(y_pred_new, target_names=target_names)
        with open(f'{reportname}_prediction_{y_pred_new}.csv', 'w') as f:
              f.write(report)
        # return logger.info(f"Compliance report generated for {reportname}")
    




# Print IAM  the classification report
container={}
iam_report = ComplianceManager().check_iam_compliance(container)
compliance = ComplianceAI(iam_report)
compliance.compliance_report_generator('iam_report')

# Print KMS the classification report
kms_container={}
kms_report = ComplianceManager().kms_compliance_audit(kms_container)
compliance = ComplianceAI(kms_report)
compliance.compliance_report_generator('kms_report')

# Print storage encryption the classification report
s3_container={}
s3_report = ComplianceManager().check_s3_encryption_at_rest(s3_container)
compliance = ComplianceAI(s3_report)
compliance.compliance_report_generator('s3_report')


# Print storage Access control management 
s3_acl_container={}
s3_acl_report = ComplianceManager().S3_secure_data_acl(s3_acl_container)
compliance = ComplianceAI(s3_acl_report)
compliance.compliance_report_generator('s3_acl_report')

# Monitoring and Logging
logg_container={}
logg_container_report = ComplianceManager().check_cloud_trail_logging(logg_container)
compliance = ComplianceAI(logg_container_report)
compliance.compliance_report_generator('logg_container_report')