# EKS WorkShop — Observability

EKS Version: 1.19
Region: Oregon / us-west-2

## 环境准备

### AWS CLI

```
# 安装和配置 AWS CLI（version 2.2.5 or later or 1.19.75 or later）

more /etc/os-release
# Amazon Linux 2

mkdir -p ~/eks
cd ~/eks

sudo yum update -y
sudo yum install unzip -y

curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install --update

which aws
# /usr/local/bin/aws

aws --version
# aws-cli/2.2.20 Python/3.8.8 Linux/4.14.238-182.421.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off


```



### EKSCTL

```
# 安装和配置 eksctl（>0.56.0）
# 参考：https://docs.aws.amazon.com/eks/latest/userguide/eksctl.html
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/eks/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

which eksctl
# /usr/local/bin/eksctl

eksctl version
# 0.57.0

```



### KUBECTL

```
# 安装和配置 `kubectl （>1.20）`
# 参考：https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html

`curl ``-``o kubectl https``:``//amazon-eks.s3.us-west-2.amazonaws.com/1.20.4/2021-04-12/bin/linux/amd64/kubectl`

`chmod ``+``x ``./``kubectl`
`sudo mv ``./``kubectl ``/``usr``/``local``/``bin`

`which kubectl`
`/``usr``/``local``/``bin``/``kubectl`

`kubectl version ``--``short`` ``--``client`
# Client Version: v1.20.4-eks-6b7464


```



### 其他相关软件及设置

```
`# 其他相关软件及设置`
`sudo yum ``-``y install jq gettext bash``-``completion moreutils git`

`echo ``'yq() {`
`  docker run --rm -i -v "${PWD}":/workdir mikefarah/yq yq "$@"`
`}'`` ``|`` tee ``-``a ``~``/.bashrc && source ~/``.``bashrc`

`# Verify the binaries are in the path and executable`
`for`` command ``in`` kubectl jq envsubst aws`
`  ``do`
`    which $command ``&>``/dev/``null`` ``&&`` echo ``"$command in path"`` ``||`` echo ``"$command NOT FOUND"`
`  ``done`

kubectl completion bash >>  ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion

eksctl completion bash >> ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion
  `  `
```



### Helm

```
# 安装配置 Helm
curl -sSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash

helm version --short
# v3.6.3+gd506314

helm repo add stable https://charts.helm.sh/stable

helm search repo stable

helm completion bash >> ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion
source <(helm completion bash)

# 查看已安装
helm list

```



## 创建 EKS 集群

### 参数方式创建控制层面（Existed VPC）

```
mkdir -p ~/eks
cd ~/eks

cat create_cluster_us_west_2_119.sh

# 自定义创建
## EKS集群名
EKS_CLUSTER_NAME=eks-us-119
## AWS区域
REGION_EKS=us-west-2
## 可自定义Tag标签信息，用于后续的费用跟踪及其他管理（可选项）
TAG="Environment=PoC,Application=TestApp1"
## 配置文件方式，可参考：
## https://github.com/weaveworks/eksctl/blob/master/examples/02-custom-vpc-cidr-no-nodes.yaml

eksctl create cluster \
  --name=$EKS_CLUSTER_NAME \
  --region=$REGION_EKS \
  --version 1.19 \
  --tags $TAG \
  --with-oidc \
  --without-nodegroup \
  --vpc-private-subnets subnet-0e3b71c46678adf2d,subnet-05961092fd00b997b,subnet-0bea0b4abcd879f3e \
  --vpc-public-subnets subnet-06453c5247887bce2,subnet-0b1c88e1242bcb5e2,subnet-0c267b9008cc5c573 \
  --asg-access \
  --external-dns-access \
  --full-ecr-access \
  --appmesh-access \
  --appmesh-preview-access \
  --alb-ingress-access

## 如需删除创建的EKS集群，可使用下面的命令
## eksctl delete cluster --name=$EKS_CLUSTER_NAME --region=$REGION_EKS

## 集群配置通常需要 10 ~ 15 分钟
## 集群将自动创建所需的VPC/安全组/IAM 角色/EKS API服务等资源

## 集群访问测试
# watch -n 2 kubectl get svc
kubectl get svc

# Get cluster
eksctl get cluster --region us-west-2

# 删除集群
# eksctl delete cluster eks-us-119 --region us-west-2


```



### 创建 非托管节点组

```
# 参数文件 + 非托管节点组 + OD 实例
mkdir -p ~/eks
cd ~/eks

## 编辑NodeGroup配置文件，文件名可自定义
## 相关配置参数可参考：https://eksctl.io/usage/schema/
## 参数部分可根据实际需求进行修改，如EC2实例类型、数量、EBS卷大小等
## 如需要启动大量EC2实例，需要提前提交提升limit申请给支持团队
## 可参考：https://docs.aws.amazon.com/zh_cn/AWSEC2/latest/UserGuide/ec2-resource-limits.html

---------------------------------------------------------------------------

cat NG-UNMANAGED-C5-2x-AZABC-OD.yaml

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: eks-us-119
  region: us-west-2

nodeGroups:
  - name: NG-C5-2x-AZABC-OD
    availabilityZones: ["us-west-2a","us-west-2b","us-west-2c"]
    privateNetworking: true
    minSize: 1
    maxSize: 10
    desiredCapacity: 3
    volumeSize: 50
    preBootstrapCommands:
      - 'sudo mkdir -p /mnt/data/'

    instancesDistribution:
      maxPrice: 1
      instanceTypes: ["c5.2xlarge"]
      onDemandBaseCapacity: 3
      onDemandPercentageAboveBaseCapacity: 100
      spotInstancePools: 1
    ssh:
      allow: true
      publicKeyName:  KEY_ORE_1
      enableSsm: true
    labels: {role: worker, NodeSize: c5.2xlarge}
    tags:
      {
      "Environment": "PoC",
      "Application": "TestApp2"
      }
    iam:
      attachPolicyARNs:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
      withAddonPolicies:
        externalDNS: true
        certManager: true
        albIngress: true
        appMesh: true
        autoScaler: true
        cloudWatch: true
        ebs: true
        efs: true
        fsx: true


## 创建NodeGroup
eksctl create nodegroup --config-file=./NG-UNMANAGED-C5-2x-AZABC-OD.yaml

## 在创建异常的情况下，需要删除之前失败的NodeGroup后重新创建
## eksctl delete nodegroup --config-file=./NG-UNMANAGED-C5-2x-AZABC-OD.yaml --approve

# 查看当前集群 NodeGroups
eksctl get nodegroup  --cluster eks-us-119 --region us-west-2

## 可手工管理NodeGroup的伸缩，如将原节点数量调整为4
eksctl scale nodegroup --cluster eks-us-119 \
    --name NG-C5-2x-AZABC-OD \
    --nodes 4 \
    --region us-west-2

## 可手工管理NodeGroup的伸缩，如将原节点数量调整为3
eksctl scale nodegroup --cluster eks-us-119 \
    --name NG-C5-2x-AZABC-OD \
    --nodes 3 \
    --region us-west-2


```



### 查看集群信息

```
`# 查看当前有效集群 Cluster`
`eksctl ``get`` cluster ``--``region us-west-2`

`# 查看当前集群 NodeGroups`
`eksctl ``get`` nodegroup  ``--``cluster eks-us-119`` ``--``region us-west-2`

`# 查看 NodeGroup 节点Role`
`STACK_NAME``=``$``(``eksctl ``get`` nodegroup ``--``cluster eks-us-119`` ``--``region us-west-2`` ``-``o json ``|`` jq ``-``r ``'.[].StackName'``)`
`ROLE_NAME``=``$``(``aws cloudformation describe``-``stack``-``resources ``--``stack``-``name $STACK_NAME --region us-west-2 ``|`` jq ``-``r ``'.StackResources[] | select(.ResourceType=="AWS::IAM::Role") | .PhysicalResourceId'``)`
`echo ``"export ROLE_NAME=${ROLE_NAME}"`` ``|`` tee ``-``a ``~/.``bash_profile

`
```



## 部署 Kubernetes Dashboard

参考：
https://docs.aws.amazon.com/eks/latest/userguide/dashboard-tutorial.html


```
## 下载Dashboard部署文件
## https://github.com/kubernetes/dashboard
wget https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.5/aio/deploy/recommended.yaml

## 修改 recommended.yaml 文件
## 在确保访问安全的情况下，在spec下，containers/kubernetes-dashboard 节下修改
## 可添加参数延长Token的过期时间（单位为分钟，默认为15分钟） 
vi recommended.yaml

    spec:
      containers:
        - name: kubernetes-dashboard
          image: kubernetesui/dashboard:v2.0.5
          imagePullPolicy: Always
          ports:
            - containerPort: 8443
              protocol: TCP
          args:
            - --auto-generate-certificates
            - --namespace=kubernetes-dashboard
            - --authentication-mode=token
            - --token-ttl=43200
            - --enable-skip-login

## 通过kubectl应用配置
kubectl apply -f recommended.yaml

# Create an eks-admin service account and cluster role binding 

vi eks-admin-service-account.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: eks-admin
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: eks-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: eks-admin
  namespace: kube-system

kubectl apply -f eks-admin-service-account.yaml

# kubectl 获取 Token
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep eks-admin | awk '{print $1}')

# 如有杀掉之前的 kubectl proxy
ps -ef|grep proxy

nohup kubectl proxy &

# 访问
http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#!/login

# 如非本地配置 kubectl，可通过 ssh -L 8001:localhost:8001 -A EC2_PUBLIC_IP 访问
ssh -L 8001:localhost:8001 -A ec2-user@18.163.170.102


```



## Install Kube-ops-view（可选）

```
helm install kube-ops-view \
stable/kube-ops-view \
--set service.type=LoadBalancer \
--set rbac.create=True

kubectl get pods -A |grep ops
# NAMESPACE              NAME                                         READY   STATUS    RESTARTS   AGE
# default                kube-ops-view-894bc75fb-rm4sq                1/1     Running   0          62m

kubectl get svc,po,deploy

helm list

NAME             NAMESPACE    REVISION    UPDATED                                    STATUS      CHART                  APP VERSION
# kube-ops-view    default      1           2020-12-07 08:04:31.707323002 +0000 UTC    deployed    kube-ops-view-1.2.4    20.4.0

kubectl get svc kube-ops-view | tail -n 1 | awk '{ print "Kube-ops-view URL = http://"$4 }'

# Kube-ops-view URL = http://a354bf2fcd6734141b73d2dc509c9a8b-1725738075.us-west-2.elb.amazonaws.com


```



## 启用 EKS 集群日志功能

参考：
https://eksctl.io/usage/cloudwatch-cluster-logging/
https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html

```
# 启用 集群日志功能（EKSCTL）
eksctl utils update-cluster-logging \
  --enable-types=all \
  --region=us-west-2 \
  --cluster=eks-us-119 \
  --approve
  
# 启用 集群日志功能（AWS CLI）
aws eks update-cluster-config \
    --region us-west-2 \
    --name eks-us-119 \
    --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
    
```

## 部署 Metrics Server

参考：
https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html

```
# 最新版本
# https://github.com/kubernetes-sigs/metrics-server/releases

kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# 配置确认
kubectl get apiservice v1beta1.metrics.k8s.io -o json | jq '.status'

{
  "conditions": [
    {
      "lastTransitionTime": "2021-01-10T06:14:52Z",
      "message": "all checks passed",
      "reason": "Passed",
      "status": "True",
      "type": "Available"
    }
  ]
}

# 查看部署
kubectl get deployment metrics-server -n kube-system

# 测试使用
# 参考：https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#top
kubectl top node
kubectl top pod -A --sort-by cpu
kubectl top pod -A --sort-by memory


```



## 部署 Prometheus and Grafana

参考：
https://www.eksworkshop.com/intermediate/240_monitoring/

### Prometheus

```
# add prometheus Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

kubectl create namespace prometheus
    
helm install prometheus prometheus-community/prometheus \
    --namespace prometheus \
    --set alertmanager.persistentVolume.storageClass="gp2" \
    --set server.persistentVolume.storageClass="gp2" 
    
kubectl get all -n prometheus

```

### Grafana

```
# add grafana Helm repo
helm repo add grafana https://grafana.github.io/helm-charts

mkdir -p ${HOME}/eks/
cd ${HOME}/eks/

cat << EoF > ${HOME}/eks/grafana.yaml
datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
    - name: Prometheus
      type: prometheus
      url: http://prometheus-server.prometheus.svc.cluster.local
      access: proxy
      isDefault: true
EoF

kubectl create namespace grafana
    
helm install grafana grafana/grafana \
    --namespace grafana \
    --set persistence.storageClassName="gp2" \
    --set persistence.enabled=true \
    --set adminPassword='EKS!sAWSome' \
    --values ${HOME}/eks/grafana.yaml \
    --set service.type=LoadBalancer

kubectl get all -n grafana

export ELB=$(kubectl get svc -n grafana grafana -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "http://$ELB"

# http://a8923cfa543964dc199771492a40b056-1041138239.us-west-2.elb.amazonaws.com
用户名：
admin
密码：
EKS!sAWSome

```

### Grafana Dashboard

```
# Import Grafana Dashboard
# Cluster Monitoring Dashboard
+ 3119 

# Pods Monitoring Dashboard
+ 6417

# K8S Control Plane
https://grafana.com/grafana/dashboards/10907
10907

# Kubernetes apiserver
https://grafana.com/grafana/dashboards/12006
12006

# 其他
https://grafana.com/grafana/dashboards/7249
https://grafana.com/grafana/dashboards/10092

```

因 Kubernetes 版本升级，部分指标废弃（如 machine_memory_bytes），导致部分 Grafana 看板数据缺失。 需手工进行看板指标的替换（如替换为 node_memory_MemTotal_bytes）
https://github.com/kubernetes/kubernetes/issues/95204
https://github.com/kubernetes/kubernetes/pull/97006
https://github.com/kubernetes/kube-state-metrics/blob/master/docs/node-metrics.md


```
`# Uninstall`

`helm uninstall prometheus ``--``namespace`` prometheus`
`kubectl ``delete`` ns prometheus`

`helm uninstall grafana ``--``namespace`` grafana`
`kubectl ``delete`` ns grafana`


```



## Container Insights with Fluent Bit

参考：
Quick Start setup for Container Insights on Amazon EKS and Kubernetes
https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-quickstart.html

https://github.com/aws-samples/amazon-cloudwatch-container-insights/tree/master/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring

使用 Fluent Bit 实现集中式容器日志记录
https://aws.amazon.com/cn/blogs/china/centralized-container-logging-fluent-bit/

### 将策略附加到工作线程节点的 IAM 角色

```
通过以下网址打开 Amazon EC2 控制台：https://console.aws.amazon.com/ec2/

选择其中的一个 EKS 工作线程节点实例并在描述中选择 IAM 角色。

在 IAM 角色页中，选择附加策略。

在策略列表中，选中 CloudWatchAgentServerPolicy 旁边的复选框。如有必要，请使用搜索框查找该策略。

选择附加策略。
```



### 部署 Fluent Bit（优化模式）及 Cloudwatch Agent

```
# 修改相关配置信息
ClusterName=eks-us-119
RegionName=us-west-2
FluentBitHttpPort='2020'
FluentBitReadFromHead='Off'
[[ ${FluentBitReadFromHead} = 'On' ]] && FluentBitReadFromTail='Off'|| FluentBitReadFromTail='On'
[[ -z ${FluentBitHttpPort} ]] && FluentBitHttpServer='Off' || FluentBitHttpServer='On'
curl https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluent-bit-quickstart.yaml | sed 's/{{cluster_name}}/'${ClusterName}'/;s/{{region_name}}/'${RegionName}'/;s/{{http_server_toggle}}/"'${FluentBitHttpServer}'"/;s/{{http_server_port}}/"'${FluentBitHttpPort}'"/;s/{{read_from_head}}/"'${FluentBitReadFromHead}'"/;s/{{read_from_tail}}/"'${FluentBitReadFromTail}'"/' | kubectl apply -f - 
kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cloudwatch-namespace.yaml

# 查看部署
kubectl get daemonset -n amazon-cloudwatch

kubectl get pods -n amazon-cloudwatch

# 删除部署
curl https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluent-bit-quickstart.yaml | sed 's/{{cluster_name}}/'${ClusterName}'/;s/{{region_name}}/'${LogRegion}'/;s/{{http_server_toggle}}/"'${FluentBitHttpServer}'"/;s/{{http_server_port}}/"'${FluentBitHttpPort}'"/;s/{{read_from_head}}/"'${FluentBitReadFromHead}'"/;s/{{read_from_tail}}/"'${FluentBitReadFromTail}'"/' | kubectl delete -f -

```



## 配置 Cloudwatch 告警（可选）

参考：
https://www.eksworkshop.com/intermediate/250_cloudwatch_container_insights/cwalarms/


## Tracing with X-Ray（可选）

参考：
https://www.eksworkshop.com/intermediate/245_x-ray/microservices/
https://aws.amazon.com/cn/blogs/compute/application-tracing-on-kubernetes-with-aws-x-ray/

```
# 
eksctl create iamserviceaccount --name xray-daemon \
    --namespace default --cluster eks-us-119 \
    --attach-policy-arn arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess \
    --region us-west-2 \
    --approve --override-existing-serviceaccounts

kubectl label serviceaccount xray-daemon app=xray-daemon

mkdir -p ~/eks/xray
cd ~/eks/xray

wget https://eksworkshop.com/intermediate/245_x-ray/daemonset.files/xray-k8s-daemonset.yaml
# 修改 TotalBufferSizeMB 配置，否则大 EC2 节点可能将导致 xray-daemon 启动失败

vi xray-k8s-daemonset.yaml

data:
  config.yaml: |-
    # Maximum buffer size in MB (minimum 3). Choose 0 to use 1% of host memory.
 **** **TotalBufferSizeMB****:** **** **20**
    
kubectl create -f xray-k8s-daemonset.yaml

kubectl describe daemonset xray-daemon

kubectl logs -l app=xray-daemon

```



```
# Deploy Example Microservices
kubectl apply -f https://eksworkshop.com/intermediate/245_x-ray/sample-front.files/x-ray-sample-front-k8s.yml

kubectl apply -f https://eksworkshop.com/intermediate/245_x-ray/sample-back.files/x-ray-sample-back-k8s.yml

kubectl describe deployments x-ray-sample-front-k8s x-ray-sample-back-k8s

kubectl describe services x-ray-sample-front-k8s x-ray-sample-back-k8s

kubectl get service x-ray-sample-front-k8s -o wide

NAME                     TYPE           CLUSTER-IP     EXTERNAL-IP                                                              PORT(S)        AGE   SELECTOR
x-ray-sample-front-k8s   LoadBalancer   172.20.229.8   a8862e82c51d948ef86d97762d8caf2a-1349520127.us-west-2.elb.amazonaws.com

# 访问
http://a8862e82c51d948ef86d97762d8caf2a-1349520127.us-west-2.elb.amazonaws.com/

```



```
# Clean Up
kubectl delete deployments x-ray-sample-front-k8s x-ray-sample-back-k8s

kubectl delete services x-ray-sample-front-k8s x-ray-sample-back-k8s

kubectl delete -f https://eksworkshop.com/intermediate/245_x-ray/daemonset.files/xray-k8s-daemonset.yaml

eksctl delete iamserviceaccount --name xray-daemon --cluster eksworkshop-eksctl


```



## 示例程序（可选）

### 示例应用部署

```
# 示例应用部署

mkdir -p ~/`environment`
cd ~/`environment`

git clone https://github.com/brentley/ecsdemo-frontend.git
git clone https://github.com/brentley/ecsdemo-nodejs.git
git clone https://github.com/brentley/ecsdemo-crystal.git

cd ~/environment/ecsdemo-nodejs
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml

kubectl get deployment ecsdemo-nodejs

cd ~/environment/ecsdemo-crystal
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml

kubectl get deployment ecsdemo-crystal

aws iam get-role --role-name "AWSServiceRoleForElasticLoadBalancing" || aws iam create-service-linked-role --aws-service-name "elasticloadbalancing.amazonaws.com"

cd ~/environment/ecsdemo-frontend
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml

cd ~/

kubectl get service ecsdemo-frontend
kubectl get service ecsdemo-frontend -o wide

# NAME               TYPE           CLUSTER-IP     EXTERNAL-IP                                                              PORT(S)        AGE   SELECTOR
# ecsdemo-frontend   LoadBalancer   10.100.79.56   a6aa583709dc441758e192e3dd927a9c-140386907.us-west-2.elb.amazonaws.com   80:31934/TCP   45s   app=ecsdemo-frontend

# 等待 ELB 创建完毕
ELB=$(kubectl get service ecsdemo-frontend -o json | jq -r '.status.loadBalancer.ingress[].hostname')
echo $ELB
# a6aa583709dc441758e192e3dd927a9c-140386907.us-west-2.elb.amazonaws.com

# curl -m3 -v $ELB

```

### 扩展应用

```
# 扩展应用
kubectl get deployments

kubectl scale deployment ecsdemo-nodejs --replicas=3
kubectl scale deployment ecsdemo-crystal --replicas=3
kubectl scale deployment ecsdemo-frontend --replicas=3

kubectl get deployments

kubectl scale deployment ecsdemo-nodejs --replicas=1
kubectl scale deployment ecsdemo-crystal --replicas=1
kubectl scale deployment ecsdemo-frontend --replicas=1

kubectl get deployments

```

### 模拟负载

```
# 模拟负载
sudo yum install siege -y

siege --version

export TEST_ELB=$(kubectl get service ecsdemo-frontend -o json | jq -r '.status.loadBalancer.ingress[].hostname')
echo $TEST_ELB

# 并发数200，持续测试 15秒
siege -q -t 15S -c 200 -i http://${TEST_ELB}

watch -n 20 siege -q -t 15S -c 200 -i http://${TEST_ELB}

```

### 删除示例应用

```
# 删除示例应用

cd ~/environment/ecsdemo-frontend
kubectl delete -f kubernetes/service.yaml
kubectl delete -f kubernetes/deployment.yaml

cd ~/environment/ecsdemo-crystal
kubectl delete -f kubernetes/service.yaml
kubectl delete -f kubernetes/deployment.yaml

cd ~/environment/ecsdemo-nodejs
kubectl delete -f kubernetes/service.yaml
kubectl delete -f kubernetes/deployment.yaml

```



## 其他

### 控制台未授权错误

```
# eksctl 创建的集群 控制台提示错误 “Unauthorized: Verify you have access to the Kubernetes cluster”
# https://docs.aws.amazon.com/zh_cn/eks/latest/userguide/add-user-role.html

# https://kubernetes.io/docs/reference/access-authn-authz/rbac/

kubectl edit -n kube-system configmap/aws-auth

data:
  mapRoles: |
    - groups:
      - system:bootstrappers
      - system:nodes
      rolearn: arn:aws:iam::861504766936:role/eksctl-eks-us-119-nodegroup-NG-UN-NodeInstanceRole-1UKYGZS0X2SP6
      username: system:node:{{EC2PrivateDNSName}}
    - groups:
      - system:bootstrappers
      - system:nodes
      rolearn: arn:aws:iam::861504766936:role/eksctl-eks-us-119-nodegroup-NG-UN-NodeInstanceRole-RBPC315WDS2N
      username: system:node:{{EC2PrivateDNSName}}
  mapUsers: |
    - groups:
        - system:masters
      userarn: arn:aws:iam::861504766936:user/admin
      username: admin



```

### NameSpace 无法删除

```
kubectl api-resources --verbs=list --namespaced -o name \
  | xargs -n 1 kubectl get --show-kind --ignore-not-found -n kubernetes-dashboard
  
# 成功
kubectl get apiservice|grep False
v1beta1.metrics.k8s.io                 kube-system/metrics-server   False (FailedDiscoveryCheck)   26d

kubectl delete apiservice v1beta1.metrics.k8s.io
apiservice.apiregistration.k8s.io "v1beta1.metrics.k8s.io" deleted

for NS in $(kubectl get ns 2>/dev/null | grep Terminating | cut -f1 -d ' '); do
  kubectl get ns $NS -o json > /tmp/$NS.json
  sed -i '' "s/\"kubernetes\"//g" /tmp/$NS.json
  kubectl replace --raw "/api/v1/namespaces/$NS/finalize" -f /tmp/$NS.json
done


```

### 多集群管理

参考：
https://kubernetes.io/zh/docs/concepts/configuration/organize-cluster-access-kubeconfig/
https://kubernetes.io/zh/docs/tasks/access-application-cluster/configure-access-multiple-clusters/
https://kubernetes.io/zh/docs/reference/kubectl/cheatsheet/


```

`sudo yum install jq ``-``y`

# 进入 Config 文件所在目录
`cd ``~/.``kube`

# 默认配置文件名为 config 
`kubectl config ``--``kubeconfig``=``config view`

# 获取 Cluster 名
`kubectl config ``--``kubeconfig``=``config view ``-``ojson``|``jq ``-``r ``'.clusters[].name'`

# 获取 Context 名
`kubectl config ``get``-``contexts`

# 获取当前 Context 名
kubectl config current-context

# 切换 Context
cd ~/.kube
kubectl config --kubeconfig=config use-context i-08bfacb20e8934e51@eks-us-119.us-west-2.eksctl.io



```



### Kubeconfig 配置

参考：
为 Amazon EKS 创建 kubeconfig
https://docs.aws.amazon.com/zh_cn/eks/latest/userguide/create-kubeconfig.html

Amazon EKS 问题排查
https://docs.aws.amazon.com/zh_cn/eks/latest/userguide/troubleshooting.html#unauthorized

我无法担任角色
https://docs.aws.amazon.com/zh_cn/IAM/latest/UserGuide/troubleshoot_roles.html#troubleshoot_roles_cant-assume-role

```
## 获知将进行STS操作的当前IAM User信息
aws sts get-caller-identity --profile hkg
{
    "UserId": "AIDAJE2VBDU67ZP6X7KEW",
    "Account": "861504766936",
    "Arn": "arn:aws:iam::861504766936:user/admin"
}


## 创建/更新本地 kubeconfig 信息
`aws eks update``-``kubeconfig ``--``name eks-us-119`` ``--``region us-west-2`` ``--``profile ``hkg`
Added new context arn:aws:eks:us-west-2:861504766936:cluster/eks-us-119 to /Users/shifei/.kube/config

## 错误信息 一
## 目前访问EKS集群的用户 与 创建EKS的用户不同
## EKS集群创建时使用 EC2 Role进行
error: You must be logged in to the server (Unauthorized)

## 使用当时创建EKS集群的EC2 Role 更新 kubeconfig 信息
`aws eks update``-``kubeconfig ``--``region us-west-2`` ``--``name eks-us-119`` ``--``role``-``arn arn``:``aws``:``iam``::``861504766936``:``role``/``ec2``-``admin``-``role --profile global`


## 错误信息 二
An error occurred (AccessDenied) when calling the AssumeRole operation: User: arn:aws:iam::861504766936:user/admin is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::861504766936:role/ec2-admin-role
Unable to connect to the server: getting credentials: exec: exit status 255
## 当前用户并非EC2 role的 “**Trusted entities**”

## 控制台修改 EC2 Role的 “Trust Relationship” policy，增加当前用户信息

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::861504766936:user/admin",
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

kubectl get svc
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.100.0.1   <none>        443/TCP   3d
```

```
## 后续如更换新的管理机，如绑定的 EC2 Role 跟之前创建 EKS 集群时的EC2 Role没有差异
## 只需在新的管理机执行以下命令即可
aws eks update-kubeconfig --region us-west-2 --name eks-us-119 --role-arn arn:aws:iam::861504766936:role/ec2-admin-role --profile global


```



## 参考文档

https://www.eksworkshop.com/


