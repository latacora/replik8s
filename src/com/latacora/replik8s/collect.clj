(ns com.latacora.replik8s.collect
  (:gen-class)
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [taoensso.timbre :as timbre])
  (:import
   (io.kubernetes.client.openapi ApiClient)
   (io.kubernetes.client.util Config KubeConfig)
   (java.io FileReader)))

(defn kubeconfig->client
  "Creates an ApiClient using the provided kubeconfig path."
  [kubeconfig-path]
  (Config/fromConfig (KubeConfig/loadKubeConfig (FileReader. kubeconfig-path))))

(defn make-request
  "Makes a raw HTTP GET request to the given API path."
  [^ApiClient client path]
  (try
    (timbre/debugf "GET %s" path)
    (let [call     (.buildCall client
                               (.getBasePath client)        ; baseUrl
                               path                         ; path
                               "GET"                        ; method
                               (java.util.ArrayList.)       ; queryParams
                               (java.util.ArrayList.)       ; collectionQueryParams
                               nil                          ; body
                               (java.util.HashMap.)         ; headerParams
                               (java.util.HashMap.)         ; cookieParams
                               (java.util.HashMap.)         ; formParams
                               (into-array String ["BearerToken"]) ; authNames
                               nil)                         ; callback
          response (.execute call)
          body     (.body response)]
      (with-open [input-stream (.byteStream body)]
        (clojure.data.json/read-str (slurp input-stream) :key-fn keyword)))
    (catch Exception e
      (timbre/errorf "Error in path %s: %s" path e))))

(defn fetch-api-endpoints
  "Fetch resources exposed by the /api endpoint"
  [api-client]
  (reduce
   (fn [data version]
     (let [version-path (str "/api/" version)
           version-data (make-request api-client version-path)
           updated-data (assoc data version-path version-data)]
       (reduce
        (fn [data resource]
          (if (contains? (set (:verbs resource)) "list")
            (let [resource-path (str version-path "/" (:name resource))
                  resource-data (make-request api-client resource-path)]
              (if-not (empty? resource-data)
                (assoc data resource-path resource-data)
                data))
            data))
        updated-data
        (:resources version-data))))
   {}
   (:versions (make-request api-client "/api"))))

(defn fetch-apis-endpoints
  "Fetch resources exposed by the /apis endpoint"
  [api-client]
  (reduce
   (fn [data group]
     (reduce
      (fn [data group-version]
        (let [group-path   (str "/apis/" (:groupVersion group-version))
              group-data   (make-request api-client group-path)
              updated-data (assoc data group-path group-data)]
          (if (empty? group-data)
            updated-data
            (reduce
             (fn [data group-resource]
               (if (contains? (set (:verbs group-resource)) "list")
                 (let [group-resource-path (str group-path "/" (:name group-resource))
                       resource-data       (make-request api-client group-resource-path)]
                   (assoc data group-resource-path resource-data))
                 data))
             updated-data
             (:resources group-data)))))
      data
      (:versions group)))
   {}
   (:groups (make-request api-client "/apis"))))

(defn fetch-all-resources
  "Fetch all resources from the Kubernetes API."
  [api-client]
  (let [api-endpoints  (fetch-api-endpoints api-client)
        apis-endpoints (fetch-apis-endpoints api-client)]
    (merge
     {"/version" (make-request api-client "/version")}
     {"/api" (make-request api-client "/api")}
     {"/apis" (make-request api-client "/apis")}
     api-endpoints
     apis-endpoints)))

(defn generate-snapshot
  "Generates a snapshot of the Kubernetes API resources and writes it to the specified output path."
  [kubeconfig-path output-path]
  (timbre/infof "Collecting with %s" kubeconfig-path)
  (let [client    (kubeconfig->client kubeconfig-path)
        host      (.getBasePath client)
        resources (fetch-all-resources client)
        metadata  {:host      host
                   :timestamp (System/currentTimeMillis)}
        snapshot  {:metadata  metadata
                   :resources resources}]

    ;; Ensure the output directory exists before writing the file.
    (let [parent-dir (.getParentFile (io/file output-path))]
      (when-not (.exists parent-dir)
        (timbre/infof "Creating snapshot directory: %s" parent-dir)
        (.mkdirs parent-dir)))

    (timbre/infof "Writing snapshot to %s" output-path)
    (spit output-path
          (with-out-str (json/pprint snapshot)))))

(comment
  (generate-snapshot "/home/user/.kube/config" "snapshots/test_snapshot.json"))
