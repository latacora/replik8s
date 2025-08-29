(ns com.latacora.replik8s.query-rules-test
  (:require [clojure.test :refer :all]
            [com.latacora.replik8s.query-utils :as qu]
            [com.latacora.replik8s.query-rules :refer [rules]]
            [datascript.core :as d]))

(def test-db (qu/directory->db "test/resources/snapshots"))

(deftest pod-rule-test
  (testing "pod rule should find a specific pod"
    (let [results (d/q '[:find ?name
                         :in $ %
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         (pod ?timestamp ?host "replik8s-test" ?name ?owner-kind ?owner-name ?spec)]
                       test-db rules)
          pod-names (set (map first results))]
      (is (contains? pod-names "host-access-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest container-rule-test
  (testing "container rule should find a specific container"
    (let [results (d/q '[:find ?name
                         :in $ %
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         (container ?timestamp ?host "replik8s-test" ?pod-name ?owner-kind ?owner-name ?spec ?container ?name ?image)]
                       test-db rules)
          container-names (set (map first results))]
      (is (contains? container-names "insecure-sc-container"))
      (is (not (contains? container-names "secure-container"))))))

(deftest roles-rule-test
  (testing "roles rule should find a specific role"
    (let [results (d/q '[:find ?role-name
                         :in $ %
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         (roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
                         [(= ?role-kind "ClusterRole")]]
                       test-db rules)
          role-names (set (map first results))]
      (is (contains? role-names "full-permissions-role")))))

(deftest bindings-rule-test
  (testing "bindings rule should find a specific binding"
    (let [results (d/q '[:find ?binding-name
                         :in $ %
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)
                         [(= ?binding-kind "ClusterRoleBinding")]]
                       test-db rules)
          binding-names (set (map first results))]
      (is (contains? binding-names "full-permissions-binding")))))

(deftest sensitive-permissions-rule-test
  (testing "sensitive-permissions rule should identify sensitive rules"
    (let [results (d/q '[:find ?role-name
                         :in $ %
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         (roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
                         [(= ?role-kind "Role")]
                         [(= ?role-namespace "replik8s-test")]
                         (sensitive-permissions ?role-rule ?issue)
                         [(= ?issue "Code execution in pods")]]
                       test-db rules)]
      (is (= #{"sensitive-role"} (set (map first results)))))))

(deftest pod-container-security-context-fields-test
  (testing "pod-container-security-context-fields rule should extract security context fields"
    (let [results (d/q '[:find ?pod-name ?container-name ?pod-privileged ?container-privileged
                         :in $ %
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
                         (pod-container-security-context-fields ?spec ?container ?pod-privileged ?pod-allow-privesc ?pod-readonly-root-fs ?pod-run-as-non-root ?pod-run-as-user ?container-privileged ?container-allow-privesc ?container-readonly-root-fs ?container-run-as-non-root ?container-run-as-user)]
                       test-db rules)]
      (is (some #(and (= "security-context-pod" (get % 0))
                      (= "insecure-sc-container" (get % 1))
                      (= "Not set" (get % 2))
                      (true? (get % 3)))
                results))
      (is (some #(and (= "secure-pod" (get % 0))
                      (= "secure-container" (get % 1))
                      (= "Not set" (get % 2))
                      (false? (get % 3)))
                results)))))
