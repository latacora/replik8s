(ns com.latacora.replik8s.query-test
  (:require [clojure.test :refer :all]
            [com.latacora.replik8s.query :as q]
            [com.latacora.replik8s.query-utils :as qu]))

(def test-db (qu/directory->db "test/resources/snapshots"))

(deftest pods-host-network-true-test
  (testing "Finds pods with hostNetwork=true"
    (let [results (q/pods-host-network-true test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "host-access-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest pods-host-ipc-true-test
  (testing "Finds pods with hostIPC=true"
    (let [results (q/pods-host-ipc-true test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "host-access-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest pods-host-pid-true-test
  (testing "Finds pods with hostPID=true"
    (let [results (q/pods-host-pid-true test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "host-access-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest pods-with-hostpath-volume-test
  (testing "Finds pods with hostPath volumes"
    (let [results (q/pods-with-hostpath-volume test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "hostpath-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest containers-with-sensitive-hostpath-mounts-test
  (testing "Finds containers with sensitive hostPath mounts"
    (let [results (q/containers-with-sensitive-hostpath-mounts test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "hostpath-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest pods-with-direct-env-vars-test
  (testing "Finds pods with direct environment variables"
    (let [results (q/pods-with-direct-env-vars test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "env-var-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest pods-with-default-service-account-test
  (testing "Finds pods using the default service account"
    (let [results (q/pods-with-default-service-account test-db)
          pod-names (set (map :pod results))]
      (is (contains? pod-names "default-sa-pod"))
      (is (not (contains? pod-names "secure-pod"))))))

(deftest container-missing-security-context-test
  (testing "Finds containers with missing security contexts"
    (let [results (q/container-missing-security-context test-db)
          container-names (set (map :container results))]
      (is (contains? container-names "missing-sc-container"))
      (is (not (contains? container-names "secure-container"))))))

(deftest containers-readonly-root-filesystem-false-test
  (testing "Finds containers with writable root filesystems"
    (let [results (q/containers-readonly-root-filesystem-false test-db)
          container-names (set (map :container results))]
      (is (contains? container-names "insecure-sc-container"))
      (is (not (contains? container-names "secure-container"))))))

(deftest containers-allow-privilege-escalation-true-test
  (testing "Finds containers that allow privilege escalation"
    (let [results (q/containers-allow-privilege-escalation-true test-db)
          container-names (set (map :container results))]
      (is (contains? container-names "insecure-sc-container"))
      (is (not (contains? container-names "secure-container"))))))

(deftest containers-privileged-true-test
  (testing "Finds privileged containers"
    (let [results (q/containers-privileged-true test-db)
          container-names (set (map :container results))]
      (is (contains? container-names "insecure-sc-container"))
      (is (not (contains? container-names "secure-container"))))))

(deftest containers-with-added-capabilities-test
  (testing "Finds containers with added capabilities"
    (let [results (q/containers-with-added-capabilities test-db)
          container-names (set (map :container results))]
      (is (contains? container-names "insecure-sc-container"))
      (is (not (contains? container-names "secure-container"))))))

(deftest rbac-full-permissions-test
  (testing "Finds subjects with full cluster permissions"
    (let [results (q/rbac-full-permissions test-db)
          subject-names (set (map :subject-name results))]
      (is (contains? subject-names "test-sa"))
      (is (not (contains? subject-names "secure-sa"))))))

(deftest rbac-sensitive-permissions-test
  (testing "Finds subjects with sensitive permissions"
    (let [results (q/rbac-sensitive-permissions test-db)
          role-names (set (map :role-name results))]
      (is (contains? role-names "sensitive-role"))
      (is (not (contains? role-names "non-sensitive-role")))
      (is (not (contains? role-names "secure-role"))))))

(deftest rbac-special-principals-with-permissions-test
  (testing "Finds special principals with permissions"
    (let [results (q/rbac-special-principals-with-permissions test-db)
          subject-names (set (map :subject-name results))]
      (is (contains? subject-names "system:unauthenticated")))))

(deftest rbac-default-service-account-permissions-test
  (testing "Finds default service accounts with permissions"
    (let [results (q/rbac-default-service-account-permissions test-db)
          subject-names (set (map :subject-name results))]
      (is (contains? subject-names "default")))))

(deftest namespaces-missing-default-deny-ingress-test
  (testing "Finds namespaces missing a default deny ingress policy"
    (let [results (q/namespaces-missing-default-deny-ingress test-db)
          namespaces (set (map :namespace results))]
      (is (contains? namespaces "replik8s-test"))
      (is (not (contains? namespaces "replik8s-test-secure"))))))

(deftest namespaces-missing-default-deny-egress-test
  (testing "Finds namespaces missing a default deny egress policy"
    (let [results (q/namespaces-missing-default-deny-egress test-db)
          namespaces (set (map :namespace results))]
      (is (contains? namespaces "replik8s-test"))
      (is (not (contains? namespaces "replik8s-test-secure"))))))

(deftest netpol-allow-all-ingress-test
  (testing "Finds network policies that allow all ingress"
    (let [results (q/netpol-allow-all-ingress test-db)
          policy-names (set (map :policy results))]
      (is (contains? policy-names "allow-all-ingress"))
      (is (not (contains? policy-names "default-deny-ingress"))))))

(deftest netpol-allow-all-egress-test
  (testing "Finds network policies that allow all egress"
    (let [results (q/netpol-allow-all-egress test-db)
          policy-names (set (map :policy results))]
      (is (contains? policy-names "allow-all-egress"))
      (is (not (contains? policy-names "default-deny-egress"))))))
