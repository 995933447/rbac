if [ $# -eq 0 ]; then
  echo "not service input"
  exit 0
fi

mkdir -p $1

protoc --mconfigschemaoutput_out=./$1\
  --mconfigschemaoutput_opt=paths=source_relative\
  --proto_path=./proto\
  --proto_path=../easymicro/proto\
  --proto_path=../mgorm/proto\
  $1.proto

shopt -s nullglob

# 匹配到的文件数组
files=($1/jsonschemaoutput/*/*.go)

if [ ${#files[@]} -ne 0 ]; then
  # 只有有文件才创建目录
  mkdir -p "jsonschema/$1"

  # 遍历文件
  for f in "${files[@]}"; do
    echo "running $f"
    go run "$f" > "jsonschema/$1/$(basename "$f").json"
  done
fi

files=($1/mconfigschemaoutput/*/*.go)

if [ ${#files[@]} -eq 0 ]; then
  exit 0
fi

# 只有有文件才创建目录
mkdir -p "mconfigschema/$1"

# 遍历文件
for f in "${files[@]}"; do
  echo "running $f"
  go run "$f" > "mconfigschema/$1/$(basename "$f").json"
done