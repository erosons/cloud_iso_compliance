    def compliance_report_generator(self, reportname: str) -> None:
        training_data_df = self.training_data
        training_data_df.columns = range(training_data_df.shape[1])
        train, test = train_test_split(training_data_df, test_size=0.3)
        x_train = train.iloc[:, 2:-1]
        y_train = train.iloc[:, -1]
        # Define all possible label values (should include all classes)
        all_labels = [0, 50, 100]
        # Map numeric labels to class names using LabelEncoder
        class_names = {0: "Non-Compliant", 50: "Partially Compliant", 100: "Compliant"}
        encoder = LabelEncoder()
        encoder.fit(all_labels)
        y_encoded = encoder.transform(y_train)

        x_test = test.iloc[:, 2:-1]
        y_test = test.iloc[:, -1]

        clf = DecisionTreeClassifier()
        clf.fit(x_train, y_encoded)

        y_pred = clf.predict(x_test)
        
        # Decode the predictions back to the original numeric labels
        y_pred_numeric = encoder.inverse_transform(y_pred)

        # Translate numeric predictions to target names using the mapping
        y_pred_names = [class_names[label] for label in y_pred_numeric]
        logger.info(y_pred_names)

        # Provide the expected target names for reporting
        target_names = [value for value in class_names.values()]
        # Evaluate using classification report
        report = classification_report(y_train, y_pred_numeric, target_names=target_names)

        accuracy = accuracy_score(y_test, y_pred_numeric)
        print(f"Accuracy: {accuracy * 100}%")

        with open(f'training_prediction_{reportname}.csv', 'w') as f:
            f.write(report)
