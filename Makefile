.PHONY: all native test test-native test-java run demo clean package

all: native test-java

native:
	$(MAKE) -C native all

test-native:
	$(MAKE) -C native test

test-java:
	cd backend && mvn test

test: test-native test-java

run: native
	cd backend && THREATCORE_PATH=../native/build/threatcore mvn spring-boot:run

demo: native
	cd backend && THREATLENS_DEMO_MODE=true THREATCORE_PATH=../native/build/threatcore mvn spring-boot:run

package: native
	cd backend && mvn -DskipTests package

clean:
	$(MAKE) -C native clean
	cd backend && mvn clean
